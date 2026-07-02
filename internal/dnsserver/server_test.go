package dnsserver

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/okmtdev/local-dns/internal/dnsmsg"
)

// fakeResolver is a fixed name table.
type fakeResolver struct {
	byName map[string]net.IP // nil value = exists but no address
	byIP   map[string]string
}

func (f *fakeResolver) ResolveName(hostname string) (net.IP, bool) {
	ip, ok := f.byName[hostname]
	return ip, ok
}

func (f *fakeResolver) ResolvePTR(ip net.IP) (string, bool) {
	h, ok := f.byIP[ip.String()]
	return h, ok
}

// stubUpstream answers every A query with 1.2.3.4 over UDP and TCP.
func stubUpstream(t *testing.T) (addr string, stop func()) {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := udp.LocalAddr().(*net.UDPAddr).Port
	tcp, err := net.Listen("tcp", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}

	answer := func(req []byte) []byte {
		q, err := dnsmsg.ParseQuestion(req)
		if err != nil {
			return nil
		}
		var answers []dnsmsg.ResourceRecord
		if q.Type == dnsmsg.TypeA {
			answers = append(answers, dnsmsg.ResourceRecord{
				Name: dnsmsg.NamePtr(12), Type: dnsmsg.TypeA, Class: dnsmsg.ClassIN,
				TTL: 300, Data: []byte{1, 2, 3, 4},
			})
		}
		resp, _ := dnsmsg.BuildReply(req, q, dnsmsg.FlagRA, dnsmsg.RcodeNoError, answers, nil)
		return resp
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, raddr, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if resp := answer(buf[:n]); resp != nil {
				udp.WriteToUDP(resp, raddr)
			}
		}
	}()
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				var lenBuf [2]byte
				if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
					return
				}
				req := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
				if _, err := io.ReadFull(conn, req); err != nil {
					return
				}
				resp := answer(req)
				out := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
				copy(out[2:], resp)
				conn.Write(out)
			}(conn)
		}
	}()

	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), func() {
		udp.Close()
		tcp.Close()
	}
}

func startServer(t *testing.T, upstream string) *Server {
	t.Helper()
	resolver := &fakeResolver{
		byName: map[string]net.IP{
			"nas":    net.ParseIP("192.168.1.50"),
			"ghost":  nil, // mapping exists, device never seen
			"router": net.ParseIP("fd00::1"),
		},
		byIP: map[string]string{"192.168.1.50": "nas"},
	}
	s := &Server{
		Addr:        "127.0.0.1:0",
		Domain:      "home.arpa",
		TTL:         30,
		Upstreams:   []string{upstream},
		SingleLabel: true,
		Resolver:    resolver,
		Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		s.Shutdown(ctx)
	})
	return s
}

func queryUDP(t *testing.T, addr string, msg []byte) []byte {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

func queryTCP(t *testing.T, addr string, msg []byte) []byte {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out[:2], uint16(len(msg)))
	copy(out[2:], msg)
	if _, err := conn.Write(out); err != nil {
		t.Fatal(err)
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func mustQuery(t *testing.T, id uint16, name string, qtype uint16) []byte {
	t.Helper()
	q, err := dnsmsg.BuildQuery(id, name, qtype, dnsmsg.ClassIN, true)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// answerIPs extracts A/AAAA rdata strings from a response.
func answerIPs(t *testing.T, resp []byte) []string {
	t.Helper()
	_, _, rrs, err := dnsmsg.ParseMessage(resp)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, rr := range rrs {
		if rr.Section != 0 {
			continue
		}
		data := resp[rr.DataStart : rr.DataStart+rr.DataLen]
		switch rr.Type {
		case dnsmsg.TypeA, dnsmsg.TypeAAAA:
			out = append(out, net.IP(data).String())
		}
	}
	return out
}

func TestManagedAQuery(t *testing.T) {
	up, stop := stubUpstream(t)
	defer stop()
	s := startServer(t, up)

	resp := queryUDP(t, s.UDPAddr().String(), mustQuery(t, 100, "NAS.Home.Arpa", dnsmsg.TypeA))
	h, _, rrs, err := dnsmsg.ParseMessage(resp)
	if err != nil {
		t.Fatal(err)
	}
	if h.ID != 100 || !h.Response() || h.Flags&dnsmsg.FlagAA == 0 {
		t.Errorf("header = %+v", h)
	}
	if got := answerIPs(t, resp); len(got) != 1 || got[0] != "192.168.1.50" {
		t.Errorf("answers = %v", got)
	}
	if rrs[0].TTL != 30 {
		t.Errorf("TTL = %d", rrs[0].TTL)
	}
}

func TestManagedAAAANoData(t *testing.T) {
	up, stop := stubUpstream(t)
	defer stop()
	s := startServer(t, up)

	resp := queryUDP(t, s.UDPAddr().String(), mustQuery(t, 101, "nas.home.arpa", dnsmsg.TypeAAAA))
	h, _, rrs, err := dnsmsg.ParseMessage(resp)
	if err != nil {
		t.Fatal(err)
	}
	if h.Rcode() != dnsmsg.RcodeNoError || h.ANCount != 0 {
		t.Errorf("want NODATA, got %+v", h)
	}
	if len(rrs) != 1 || rrs[0].Type != dnsmsg.TypeSOA || rrs[0].Section != 1 {
		t.Errorf("authority = %+v", rrs)
	}
}

func TestManagedIPv6AAAA(t *testing.T) {
	up, stop := stubUpstream(t)
	defer stop()
	s := startServer(t, up)

	resp := queryUDP(t, s.UDPAddr().String(), mustQuery(t, 102, "router.home.arpa", dnsmsg.TypeAAAA))
	if got := answerIPs(t, resp); len(got) != 1 || got[0] != "fd00::1" {
		t.Errorf("answers = %v", got)
	}
}

func TestNXDomainWithSOA(t *testing.T) {
	up, stop := stubUpstream(t)
	defer stop()
	s := startServer(t, up)

	resp := queryUDP(t, s.UDPAddr().String(), mustQuery(t, 103, "missing.home.arpa", dnsmsg.TypeA))
	h, _, rrs, err := dnsmsg.ParseMessage(resp)
	if err != nil {
		t.Fatal(err)
	}
	if h.Rcode() != dnsmsg.RcodeNXDomain {
		t.Errorf("rcode = %d, want NXDOMAIN", h.Rcode())
	}
	if len(rrs) != 1 || rrs[0].Type != dnsmsg.TypeSOA || rrs[0].Name != "home.arpa" {
		t.Errorf("authority = %+v", rrs)
	}
}

func TestGhostMappingNoData(t *testing.T) {
	up, stop := stubUpstream(t)
	defer stop()
	s := startServer(t, up)

	resp := queryUDP(t, s.UDPAddr().String(), mustQuery(t, 104, "ghost.home.arpa", dnsmsg.TypeA))
	h, _, _, err := dnsmsg.ParseMessage(resp)
	if err != nil {
		t.Fatal(err)
	}
	if h.Rcode() != dnsmsg.RcodeNoError || h.ANCount != 0 {
		t.Errorf("want NODATA for ghost, got %+v", h)
	}
}

func TestSingleLabel(t *testing.T) {
	up, stop := stubUpstream(t)
	defer stop()
	s := startServer(t, up)

	resp := queryUDP(t, s.UDPAddr().String(), mustQuery(t, 105, "nas", dnsmsg.TypeA))
	if got := answerIPs(t, resp); len(got) != 1 || got[0] != "192.168.1.50" {
		t.Errorf("single-label answers = %v", got)
	}

	// Unknown single-label goes upstream (stub answers 1.2.3.4).
	resp = queryUDP(t, s.UDPAddr().String(), mustQuery(t, 106, "elsewhere", dnsmsg.TypeA))
	if got := answerIPs(t, resp); len(got) != 1 || got[0] != "1.2.3.4" {
		t.Errorf("forwarded single-label = %v", got)
	}
}

func TestPTR(t *testing.T) {
	up, stop := stubUpstream(t)
	defer stop()
	s := startServer(t, up)

	resp := queryUDP(t, s.UDPAddr().String(), mustQuery(t, 107, "50.1.168.192.in-addr.arpa", dnsmsg.TypePTR))
	_, _, rrs, err := dnsmsg.ParseMessage(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(rrs) != 1 || rrs[0].Type != dnsmsg.TypePTR {
		t.Fatalf("rrs = %+v", rrs)
	}
	target, err := dnsmsg.DecodeNameAt(resp, rrs[0].DataStart)
	if err != nil || target != "nas.home.arpa" {
		t.Errorf("PTR target = %q, %v", target, err)
	}
}

func TestForwardUDPAndTCP(t *testing.T) {
	up, stop := stubUpstream(t)
	defer stop()
	s := startServer(t, up)

	resp := queryUDP(t, s.UDPAddr().String(), mustQuery(t, 108, "example.com", dnsmsg.TypeA))
	h, _, _, err := dnsmsg.ParseMessage(resp)
	if err != nil {
		t.Fatal(err)
	}
	if h.ID != 108 {
		t.Errorf("relayed ID = %d", h.ID)
	}
	if got := answerIPs(t, resp); len(got) != 1 || got[0] != "1.2.3.4" {
		t.Errorf("forwarded = %v", got)
	}

	// Same over TCP; also exercise a managed name over TCP.
	resp = queryTCP(t, s.TCPAddr().String(), mustQuery(t, 109, "example.com", dnsmsg.TypeA))
	if got := answerIPs(t, resp); len(got) != 1 || got[0] != "1.2.3.4" {
		t.Errorf("forwarded tcp = %v", got)
	}
	resp = queryTCP(t, s.TCPAddr().String(), mustQuery(t, 110, "nas.home.arpa", dnsmsg.TypeA))
	if got := answerIPs(t, resp); len(got) != 1 || got[0] != "192.168.1.50" {
		t.Errorf("managed tcp = %v", got)
	}
}

func TestApexSOA(t *testing.T) {
	up, stop := stubUpstream(t)
	defer stop()
	s := startServer(t, up)

	resp := queryUDP(t, s.UDPAddr().String(), mustQuery(t, 111, "home.arpa", dnsmsg.TypeSOA))
	_, _, rrs, err := dnsmsg.ParseMessage(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(rrs) != 1 || rrs[0].Type != dnsmsg.TypeSOA || rrs[0].Section != 0 {
		t.Errorf("apex SOA = %+v", rrs)
	}
}

func TestUpstreamFailureServfail(t *testing.T) {
	// Reserve a port and close it so nothing listens there.
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	dead := l.LocalAddr().String()
	l.Close()

	s := startServer(t, dead)
	resp := queryUDP(t, s.UDPAddr().String(), mustQuery(t, 112, "example.com", dnsmsg.TypeA))
	h, _, _, err := dnsmsg.ParseMessage(resp)
	if err != nil {
		t.Fatal(err)
	}
	if h.Rcode() != dnsmsg.RcodeServFail {
		t.Errorf("rcode = %d, want SERVFAIL", h.Rcode())
	}
}

func TestResponsePacketsDropped(t *testing.T) {
	up, stop := stubUpstream(t)
	defer stop()
	s := startServer(t, up)

	// A response-flagged packet must be ignored (no reply, no crash).
	conn, err := net.Dial("udp", s.UDPAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	msg := mustQuery(t, 113, "nas.home.arpa", dnsmsg.TypeA)
	msg[2] |= 0x80 // QR bit
	conn.Write(msg)
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 512)
	if n, err := conn.Read(buf); err == nil {
		t.Errorf("got %d-byte reply to a response packet", n)
	}

	// The server must still work afterwards.
	resp := queryUDP(t, s.UDPAddr().String(), mustQuery(t, 114, "nas.home.arpa", dnsmsg.TypeA))
	if got := answerIPs(t, resp); len(got) != 1 {
		t.Errorf("server broken after junk: %v", got)
	}
}
