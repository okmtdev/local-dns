package scanner

import (
	"encoding/binary"
	"net"
	"strings"
	"time"

	"github.com/okmtdev/local-dns/internal/dnsmsg"
)

// probeHostname tries to learn a human-friendly hostname for ip,
// first via mDNS reverse lookup (Apple/Linux/Android devices), then
// via a NetBIOS node status query (Windows). Best effort: returns ""
// when nothing answered.
func probeHostname(ip net.IP, timeout time.Duration) string {
	if h := mdnsReverseLookup(ip, timeout); h != "" {
		return h
	}
	return nbnsNodeStatus(ip, timeout)
}

// mdnsReverseLookup sends a PTR question for the address to the mDNS
// multicast group with the unicast-response bit set and waits briefly
// for a unicast reply.
func mdnsReverseLookup(ip net.IP, timeout time.Duration) string {
	v4 := ip.To4()
	if v4 == nil {
		return ""
	}
	qname := dnsmsg.ReverseName(v4)
	// Class IN with the top "QU" bit requesting a unicast response.
	query, err := dnsmsg.BuildQuery(0, qname, dnsmsg.TypePTR, dnsmsg.ClassIN|0x8000, false)
	if err != nil {
		return ""
	}
	conn, err := net.Dial("udp4", "224.0.0.251:5353")
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(query); err != nil {
		return ""
	}
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return ""
		}
		if name := extractMDNSPtr(buf[:n], qname); name != "" {
			return name
		}
	}
}

// extractMDNSPtr pulls the PTR target for qname out of an mDNS reply.
func extractMDNSPtr(msg []byte, qname string) string {
	h, _, rrs, err := dnsmsg.ParseMessage(msg)
	if err != nil || !h.Response() {
		return ""
	}
	for _, rr := range rrs {
		// mDNS sets the cache-flush bit in the class; mask it off.
		if rr.Type != dnsmsg.TypePTR || rr.Class&0x7FFF != dnsmsg.ClassIN {
			continue
		}
		if rr.Name != qname {
			continue
		}
		target, err := dnsmsg.DecodeNameAt(msg, rr.DataStart)
		if err != nil || target == "" {
			continue
		}
		host := strings.TrimSuffix(target, ".local")
		host = strings.TrimSuffix(host, ".")
		if host != "" {
			return host
		}
	}
	return ""
}

// nbnsNodeStatus sends a NetBIOS node status request (NBSTAT, the
// wildcard "*" name) directly to the host and extracts its machine
// name from the reply. Windows hosts answer this on UDP 137.
func nbnsNodeStatus(ip net.IP, timeout time.Duration) string {
	conn, err := net.Dial("udp4", net.JoinHostPort(ip.String(), "137"))
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(nbnsQuery()); err != nil {
		return ""
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}
	return parseNBNSReply(buf[:n])
}

// nbnsQuery builds the fixed 50-byte NBSTAT query for the wildcard
// name "*" (first-level encoded as "CK" + 30x"A").
func nbnsQuery() []byte {
	out := make([]byte, 0, 50)
	hdr := [12]byte{}
	binary.BigEndian.PutUint16(hdr[0:2], 0x1D7E) // transaction id (arbitrary)
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT
	out = append(out, hdr[:]...)
	out = append(out, 0x20) // encoded name length: 32
	out = append(out, 'C', 'K')
	for i := 0; i < 30; i++ {
		out = append(out, 'A')
	}
	out = append(out, 0x00)       // name terminator
	out = append(out, 0x00, 0x21) // QTYPE NBSTAT
	out = append(out, 0x00, 0x01) // QCLASS IN
	return out
}

// parseNBNSReply extracts the first unique workstation name from a
// node status response.
func parseNBNSReply(msg []byte) string {
	if len(msg) < 12 {
		return ""
	}
	an := binary.BigEndian.Uint16(msg[6:8])
	if an == 0 {
		return ""
	}
	off := 12
	// Skip echoed questions if any.
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	for i := 0; i < qd; i++ {
		o := skipNBName(msg, off)
		if o < 0 || o+4 > len(msg) {
			return ""
		}
		off = o + 4
	}
	// Answer: name + type(2) + class(2) + ttl(4) + rdlength(2).
	off = skipNBName(msg, off)
	if off < 0 || off+10 > len(msg) {
		return ""
	}
	if binary.BigEndian.Uint16(msg[off:off+2]) != 0x0021 {
		return ""
	}
	off += 10
	if off >= len(msg) {
		return ""
	}
	numNames := int(msg[off])
	off++
	for i := 0; i < numNames; i++ {
		if off+18 > len(msg) {
			return ""
		}
		raw := msg[off : off+15]
		suffix := msg[off+15]
		flags := binary.BigEndian.Uint16(msg[off+16 : off+18])
		off += 18
		const groupName = 0x8000
		if suffix != 0x00 || flags&groupName != 0 {
			continue // group names / non-workstation suffixes
		}
		name := strings.TrimRight(string(raw), " \x00")
		if name == "" || strings.ContainsAny(name, "\x00\x01\x02") {
			continue
		}
		return name
	}
	return ""
}

// skipNBName advances past a NetBIOS-encoded name (which may be a
// compression pointer) and returns the new offset, or -1 on error.
func skipNBName(msg []byte, off int) int {
	if off >= len(msg) {
		return -1
	}
	if msg[off]&0xC0 == 0xC0 {
		if off+2 > len(msg) {
			return -1
		}
		return off + 2
	}
	for off < len(msg) {
		l := int(msg[off])
		if l == 0 {
			return off + 1
		}
		off += 1 + l
	}
	return -1
}
