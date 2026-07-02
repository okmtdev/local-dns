// Package dnsmsg implements the subset of the DNS wire format
// (RFC 1035) needed by local-dns: parsing queries, building
// authoritative replies, and decoding answers of probe responses.
//
// It intentionally avoids third-party dependencies. Queries that are
// not handled locally are relayed to upstreams as raw bytes, so full
// message parsing is only needed for the question section and for
// small, well-known probe replies (mDNS).
package dnsmsg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Record types and classes used by local-dns.
const (
	TypeA    uint16 = 1
	TypeNS   uint16 = 2
	TypeSOA  uint16 = 6
	TypePTR  uint16 = 12
	TypeTXT  uint16 = 16
	TypeAAAA uint16 = 28
	TypeANY  uint16 = 255

	ClassIN uint16 = 1
)

// Header flag bits.
const (
	FlagQR uint16 = 1 << 15
	FlagAA uint16 = 1 << 10
	FlagTC uint16 = 1 << 9
	FlagRD uint16 = 1 << 8
	FlagRA uint16 = 1 << 7
)

// Response codes.
const (
	RcodeNoError  = 0
	RcodeFormErr  = 1
	RcodeServFail = 2
	RcodeNXDomain = 3
	RcodeNotImp   = 4
	RcodeRefused  = 5
)

const headerLen = 12

var (
	errShort   = errors.New("dnsmsg: message too short")
	errBadName = errors.New("dnsmsg: malformed name")
)

// Header is the fixed 12-byte DNS message header.
type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// ParseHeader decodes the header of msg.
func ParseHeader(msg []byte) (Header, error) {
	if len(msg) < headerLen {
		return Header{}, errShort
	}
	return Header{
		ID:      binary.BigEndian.Uint16(msg[0:2]),
		Flags:   binary.BigEndian.Uint16(msg[2:4]),
		QDCount: binary.BigEndian.Uint16(msg[4:6]),
		ANCount: binary.BigEndian.Uint16(msg[6:8]),
		NSCount: binary.BigEndian.Uint16(msg[8:10]),
		ARCount: binary.BigEndian.Uint16(msg[10:12]),
	}, nil
}

// Response reports whether the QR bit is set.
func (h Header) Response() bool { return h.Flags&FlagQR != 0 }

// Opcode returns the operation code (0 = standard query).
func (h Header) Opcode() int { return int(h.Flags >> 11 & 0xF) }

// Rcode returns the response code.
func (h Header) Rcode() int { return int(h.Flags & 0xF) }

func (h Header) append(b []byte) []byte {
	var hdr [headerLen]byte
	binary.BigEndian.PutUint16(hdr[0:2], h.ID)
	binary.BigEndian.PutUint16(hdr[2:4], h.Flags)
	binary.BigEndian.PutUint16(hdr[4:6], h.QDCount)
	binary.BigEndian.PutUint16(hdr[6:8], h.ANCount)
	binary.BigEndian.PutUint16(hdr[8:10], h.NSCount)
	binary.BigEndian.PutUint16(hdr[10:12], h.ARCount)
	return append(b, hdr[:]...)
}

// Question is a parsed question section entry.
type Question struct {
	// Name is the query name: lowercase, dot-separated, no trailing dot
	// ("" means the root).
	Name  string
	Type  uint16
	Class uint16
	// End is the offset of the first byte after this question. For
	// single-question messages the bytes msg[12:End] are the question
	// section and can be echoed verbatim into a reply.
	End int
}

// ParseQuestion parses the first (and for our purposes only) question
// of msg. Compression pointers are rejected: real-world queries never
// compress the question name.
func ParseQuestion(msg []byte) (Question, error) {
	name, off, err := decodeNameUncompressed(msg, headerLen)
	if err != nil {
		return Question{}, err
	}
	if off+4 > len(msg) {
		return Question{}, errShort
	}
	return Question{
		Name:  name,
		Type:  binary.BigEndian.Uint16(msg[off : off+2]),
		Class: binary.BigEndian.Uint16(msg[off+2 : off+4]),
		End:   off + 4,
	}, nil
}

// decodeNameUncompressed reads a name that must not contain
// compression pointers, returning the lowercase textual form.
func decodeNameUncompressed(msg []byte, off int) (string, int, error) {
	var sb strings.Builder
	total := 0
	for {
		if off >= len(msg) {
			return "", 0, errShort
		}
		l := int(msg[off])
		if l == 0 {
			off++
			return sb.String(), off, nil
		}
		if l&0xC0 != 0 {
			return "", 0, errBadName
		}
		if off+1+l > len(msg) {
			return "", 0, errShort
		}
		total += l + 1
		if total > 255 {
			return "", 0, errBadName
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		for _, c := range msg[off+1 : off+1+l] {
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			sb.WriteByte(c)
		}
		off += 1 + l
	}
}

// DecodeNameAt decodes a possibly compressed name at offset off of the
// whole message. Used for parsing RDATA of probe responses.
func DecodeNameAt(msg []byte, off int) (string, error) {
	name, _, err := decodeName(msg, off, 0)
	return name, err
}

func decodeName(msg []byte, off, depth int) (string, int, error) {
	if depth > 16 {
		return "", 0, errBadName
	}
	var sb strings.Builder
	next := -1
	total := 0
	for {
		if off >= len(msg) {
			return "", 0, errShort
		}
		b := int(msg[off])
		switch {
		case b == 0:
			if next < 0 {
				next = off + 1
			}
			return sb.String(), next, nil
		case b&0xC0 == 0xC0:
			if off+1 >= len(msg) {
				return "", 0, errShort
			}
			ptr := (b&0x3F)<<8 | int(msg[off+1])
			if next < 0 {
				next = off + 2
			}
			part, _, err := decodeName(msg, ptr, depth+1)
			if err != nil {
				return "", 0, err
			}
			if part != "" {
				if sb.Len() > 0 {
					sb.WriteByte('.')
				}
				sb.WriteString(part)
			}
			return sb.String(), next, nil
		case b&0xC0 != 0:
			return "", 0, errBadName
		default:
			if off+1+b > len(msg) {
				return "", 0, errShort
			}
			total += b + 1
			if total > 255 {
				return "", 0, errBadName
			}
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			for _, c := range msg[off+1 : off+1+b] {
				if 'A' <= c && c <= 'Z' {
					c += 'a' - 'A'
				}
				sb.WriteByte(c)
			}
			off += 1 + b
		}
	}
}

// EncodeName converts "a.b.c" (no trailing dot; "" = root) to wire
// format without compression.
func EncodeName(name string) ([]byte, error) {
	if name == "" || name == "." {
		return []byte{0}, nil
	}
	name = strings.TrimSuffix(name, ".")
	out := make([]byte, 0, len(name)+2)
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return nil, errBadName
		}
		if len(label) > 63 {
			return nil, errBadName
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	if len(out)+1 > 255 {
		return nil, errBadName
	}
	return append(out, 0), nil
}

// NamePtr returns a compression pointer to the given message offset.
// NamePtr(12) points at the question name of a standard reply.
func NamePtr(off int) []byte {
	return []byte{0xC0 | byte(off>>8), byte(off)}
}

// ResourceRecord is a record to be written into a reply.
type ResourceRecord struct {
	// Name is the wire-encoded owner name (e.g. NamePtr(12) or the
	// output of EncodeName).
	Name  []byte
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte
}

func (rr ResourceRecord) append(b []byte) []byte {
	b = append(b, rr.Name...)
	var fixed [10]byte
	binary.BigEndian.PutUint16(fixed[0:2], rr.Type)
	binary.BigEndian.PutUint16(fixed[2:4], rr.Class)
	binary.BigEndian.PutUint32(fixed[4:8], rr.TTL)
	binary.BigEndian.PutUint16(fixed[8:10], uint16(len(rr.Data)))
	b = append(b, fixed[:]...)
	return append(b, rr.Data...)
}

// BuildReply builds a reply to the single-question request req/q.
// The question section is echoed byte-for-byte (preserving the case of
// the query name). flags should contain the extra bits to set (FlagAA,
// FlagRA); QR, opcode and RD are handled automatically.
func BuildReply(req []byte, q Question, flags uint16, rcode int, answers, authority []ResourceRecord) ([]byte, error) {
	reqHdr, err := ParseHeader(req)
	if err != nil {
		return nil, err
	}
	if q.End > len(req) || q.End < headerLen {
		return nil, errShort
	}
	h := Header{
		ID:      reqHdr.ID,
		Flags:   FlagQR | reqHdr.Flags&(0xF<<11) | reqHdr.Flags&FlagRD | flags | uint16(rcode&0xF),
		QDCount: 1,
		ANCount: uint16(len(answers)),
		NSCount: uint16(len(authority)),
	}
	out := make([]byte, 0, 512)
	out = h.append(out)
	out = append(out, req[headerLen:q.End]...)
	for _, rr := range answers {
		out = rr.append(out)
	}
	for _, rr := range authority {
		out = rr.append(out)
	}
	return out, nil
}

// BuildHeaderOnly builds a section-less reply carrying just an rcode.
// Used when the request could not be parsed beyond its header.
func BuildHeaderOnly(reqID, reqFlags uint16, rcode int) []byte {
	h := Header{
		ID:    reqID,
		Flags: FlagQR | reqFlags&(0xF<<11) | reqFlags&FlagRD | FlagRA | uint16(rcode&0xF),
	}
	return h.append(make([]byte, 0, headerLen))
}

// BuildQuery builds a standard single-question query.
func BuildQuery(id uint16, name string, qtype, qclass uint16, rd bool) ([]byte, error) {
	wire, err := EncodeName(name)
	if err != nil {
		return nil, err
	}
	h := Header{ID: id, QDCount: 1}
	if rd {
		h.Flags |= FlagRD
	}
	out := h.append(make([]byte, 0, headerLen+len(wire)+4))
	out = append(out, wire...)
	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:2], qtype)
	binary.BigEndian.PutUint16(tail[2:4], qclass)
	return append(out, tail[:]...), nil
}

// SOAData encodes SOA RDATA.
func SOAData(mname, rname string, serial, refresh, retry, expire, minTTL uint32) ([]byte, error) {
	mw, err := EncodeName(mname)
	if err != nil {
		return nil, err
	}
	rw, err := EncodeName(rname)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(mw)+len(rw)+20)
	out = append(out, mw...)
	out = append(out, rw...)
	var nums [20]byte
	binary.BigEndian.PutUint32(nums[0:4], serial)
	binary.BigEndian.PutUint32(nums[4:8], refresh)
	binary.BigEndian.PutUint32(nums[8:12], retry)
	binary.BigEndian.PutUint32(nums[12:16], expire)
	binary.BigEndian.PutUint32(nums[16:20], minTTL)
	return append(out, nums[:]...), nil
}

// ParsedRR is a resource record decoded from a received message.
type ParsedRR struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	// DataStart/DataLen locate the RDATA inside the original message,
	// so names inside RDATA can be decoded with DecodeNameAt.
	DataStart int
	DataLen   int
	// Section is 0 for answer, 1 for authority, 2 for additional.
	Section int
}

// ParseMessage decodes header, questions and all resource records of a
// received message (used for mDNS probe replies and in tests).
func ParseMessage(msg []byte) (Header, []Question, []ParsedRR, error) {
	h, err := ParseHeader(msg)
	if err != nil {
		return Header{}, nil, nil, err
	}
	off := headerLen
	questions := make([]Question, 0, h.QDCount)
	for i := 0; i < int(h.QDCount); i++ {
		name, next, err := decodeName(msg, off, 0)
		if err != nil {
			return h, nil, nil, err
		}
		if next+4 > len(msg) {
			return h, nil, nil, errShort
		}
		questions = append(questions, Question{
			Name:  name,
			Type:  binary.BigEndian.Uint16(msg[next : next+2]),
			Class: binary.BigEndian.Uint16(msg[next+2 : next+4]),
			End:   next + 4,
		})
		off = next + 4
	}
	counts := []int{int(h.ANCount), int(h.NSCount), int(h.ARCount)}
	var rrs []ParsedRR
	for section, count := range counts {
		for i := 0; i < count; i++ {
			name, next, err := decodeName(msg, off, 0)
			if err != nil {
				return h, questions, rrs, err
			}
			if next+10 > len(msg) {
				return h, questions, rrs, errShort
			}
			rdlen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
			dataStart := next + 10
			if dataStart+rdlen > len(msg) {
				return h, questions, rrs, errShort
			}
			rrs = append(rrs, ParsedRR{
				Name:      name,
				Type:      binary.BigEndian.Uint16(msg[next : next+2]),
				Class:     binary.BigEndian.Uint16(msg[next+2 : next+4]),
				TTL:       binary.BigEndian.Uint32(msg[next+4 : next+8]),
				DataStart: dataStart,
				DataLen:   rdlen,
				Section:   section,
			})
			off = dataStart + rdlen
		}
	}
	return h, questions, rrs, nil
}

// ReverseName returns the in-addr.arpa name for an IPv4 address.
func ReverseName(ip4 []byte) string {
	if len(ip4) != 4 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", ip4[3], ip4[2], ip4[1], ip4[0])
}

// ParseReverseName parses "d.c.b.a.in-addr.arpa" into the IPv4 address
// a.b.c.d, returning nil when the name is not an IPv4 reverse name.
func ParseReverseName(name string) []byte {
	const suffix = ".in-addr.arpa"
	if !strings.HasSuffix(name, suffix) {
		return nil
	}
	parts := strings.Split(strings.TrimSuffix(name, suffix), ".")
	if len(parts) != 4 {
		return nil
	}
	ip := make([]byte, 4)
	for i, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return nil
		}
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return nil
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return nil
		}
		// parts[0] is the last octet.
		ip[3-i] = byte(n)
	}
	return ip
}
