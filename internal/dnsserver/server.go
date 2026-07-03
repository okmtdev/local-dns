// Package dnsserver implements the DNS server of local-dns.
//
// Queries for names under the configured domain are answered
// authoritatively from the mapping store; everything else is relayed
// to the upstream resolvers as raw bytes (preserving EDNS/DNSSEC
// options untouched), which makes local-dns usable as the primary DNS
// server of a home network.
package dnsserver

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/okmtdev/local-dns/internal/dnsmsg"
)

const (
	maxUDPQuery   = 4096
	maxTCPMsg     = 65535
	udpTimeout    = 3 * time.Second
	tcpTimeout    = 5 * time.Second
	tcpIdle       = 30 * time.Second
	maxTCPQueries = 64 // per connection
)

// Resolver resolves managed names; implemented by *store.Store.
type Resolver interface {
	// ResolveName maps a relative hostname to an IP. found reports
	// whether the name exists at all (nil IP + true = NODATA).
	ResolveName(hostname string) (net.IP, bool)
	// ResolvePTR maps an IP back to a relative hostname.
	ResolvePTR(ip net.IP) (string, bool)
}

// Server serves DNS on UDP and TCP.
type Server struct {
	Addr        string
	Domain      string // zone, e.g. "home.arpa"
	TTL         uint32
	Upstreams   []string
	SingleLabel bool
	Resolver    Resolver
	Log         *slog.Logger

	udp *net.UDPConn
	tcp net.Listener
	wg  sync.WaitGroup
}

// Start binds the UDP and TCP listeners and begins serving.
func (s *Server) Start() error {
	uaddr, err := net.ResolveUDPAddr("udp", s.Addr)
	if err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		return err
	}
	tcp, err := net.Listen("tcp", s.Addr)
	if err != nil {
		udp.Close()
		return err
	}
	s.udp = udp
	s.tcp = tcp
	s.wg.Add(2)
	go s.serveUDP()
	go s.serveTCP()
	return nil
}

// UDPAddr returns the bound UDP address (after Start).
func (s *Server) UDPAddr() net.Addr { return s.udp.LocalAddr() }

// TCPAddr returns the bound TCP address (after Start).
func (s *Server) TCPAddr() net.Addr { return s.tcp.Addr() }

// Shutdown closes the listeners and waits for the serve loops.
func (s *Server) Shutdown(ctx context.Context) {
	if s.udp != nil {
		s.udp.Close()
	}
	if s.tcp != nil {
		s.tcp.Close()
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (s *Server) serveUDP() {
	defer s.wg.Done()
	buf := make([]byte, maxUDPQuery)
	for {
		n, raddr, err := s.udp.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.Log.Debug("udp read error", "error", err)
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go func(pkt []byte, raddr *net.UDPAddr) {
			if resp := s.handle(pkt, "udp"); resp != nil {
				s.udp.WriteToUDP(resp, raddr) //nolint:errcheck
			}
		}(pkt, raddr)
	}
}

func (s *Server) serveTCP() {
	defer s.wg.Done()
	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.Log.Debug("tcp accept error", "error", err)
			continue
		}
		go s.serveTCPConn(conn)
	}
}

func (s *Server) serveTCPConn(conn net.Conn) {
	defer conn.Close()
	for i := 0; i < maxTCPQueries; i++ {
		conn.SetReadDeadline(time.Now().Add(tcpIdle))
		req, err := readTCPMsg(conn)
		if err != nil {
			return
		}
		resp := s.handle(req, "tcp")
		if resp == nil {
			return
		}
		conn.SetWriteDeadline(time.Now().Add(tcpTimeout))
		if err := writeTCPMsg(conn, resp); err != nil {
			return
		}
	}
}

// handle processes one raw DNS message and returns the raw response
// (nil = drop).
func (s *Server) handle(req []byte, transport string) []byte {
	h, err := dnsmsg.ParseHeader(req)
	if err != nil || h.Response() {
		return nil
	}
	// Non-standard queries and multi-question messages are relayed
	// verbatim; upstream servers know better how to reject them.
	if h.Opcode() != 0 || h.QDCount != 1 {
		return s.forward(req, transport, dnsmsg.Question{}, false)
	}
	q, err := dnsmsg.ParseQuestion(req)
	if err != nil {
		return dnsmsg.BuildHeaderOnly(h.ID, h.Flags, dnsmsg.RcodeFormErr)
	}
	if q.Class != dnsmsg.ClassIN {
		return s.forward(req, transport, q, true)
	}
	if resp := s.local(req, q); resp != nil {
		return resp
	}
	return s.forward(req, transport, q, true)
}

// local answers queries this server is responsible for; it returns nil
// when the query should be forwarded instead.
func (s *Server) local(req []byte, q dnsmsg.Question) []byte {
	name := q.Name
	switch {
	case name == s.Domain:
		return s.answerApex(req, q)
	case strings.HasSuffix(name, "."+s.Domain):
		hostname := strings.TrimSuffix(name, "."+s.Domain)
		return s.answerName(req, q, hostname)
	case q.Type == dnsmsg.TypePTR:
		ip := dnsmsg.ParseReverseName(name)
		if ip == nil {
			return nil
		}
		hostname, ok := s.Resolver.ResolvePTR(net.IP(ip))
		if !ok {
			return nil // unknown address: let upstream (e.g. router) try
		}
		return s.answerPTR(req, q, hostname)
	case s.SingleLabel && name != "" && !strings.Contains(name, "."):
		if _, found := s.Resolver.ResolveName(name); found {
			return s.answerName(req, q, name)
		}
		return nil
	default:
		return nil
	}
}

func (s *Server) answerApex(req []byte, q dnsmsg.Question) []byte {
	soa := s.soaRecord()
	var answers, authority []dnsmsg.ResourceRecord
	if q.Type == dnsmsg.TypeSOA || q.Type == dnsmsg.TypeANY {
		answers = []dnsmsg.ResourceRecord{soa}
	} else {
		authority = []dnsmsg.ResourceRecord{soa}
	}
	return s.reply(req, q, dnsmsg.RcodeNoError, answers, authority)
}

func (s *Server) answerName(req []byte, q dnsmsg.Question, hostname string) []byte {
	ip, found := s.Resolver.ResolveName(hostname)
	if !found {
		return s.reply(req, q, dnsmsg.RcodeNXDomain, nil, []dnsmsg.ResourceRecord{s.soaRecord()})
	}
	var answers []dnsmsg.ResourceRecord
	if ip != nil {
		v4 := ip.To4()
		wantA := q.Type == dnsmsg.TypeA || q.Type == dnsmsg.TypeANY
		wantAAAA := q.Type == dnsmsg.TypeAAAA || q.Type == dnsmsg.TypeANY
		if wantA && v4 != nil {
			answers = append(answers, dnsmsg.ResourceRecord{
				Name: dnsmsg.NamePtr(12), Type: dnsmsg.TypeA, Class: dnsmsg.ClassIN,
				TTL: s.TTL, Data: v4,
			})
		}
		if wantAAAA && v4 == nil {
			answers = append(answers, dnsmsg.ResourceRecord{
				Name: dnsmsg.NamePtr(12), Type: dnsmsg.TypeAAAA, Class: dnsmsg.ClassIN,
				TTL: s.TTL, Data: ip.To16(),
			})
		}
	}
	var authority []dnsmsg.ResourceRecord
	if len(answers) == 0 {
		authority = []dnsmsg.ResourceRecord{s.soaRecord()} // NODATA
	}
	return s.reply(req, q, dnsmsg.RcodeNoError, answers, authority)
}

func (s *Server) answerPTR(req []byte, q dnsmsg.Question, hostname string) []byte {
	fqdn, err := dnsmsg.EncodeName(hostname + "." + s.Domain)
	if err != nil {
		return s.reply(req, q, dnsmsg.RcodeServFail, nil, nil)
	}
	answers := []dnsmsg.ResourceRecord{{
		Name: dnsmsg.NamePtr(12), Type: dnsmsg.TypePTR, Class: dnsmsg.ClassIN,
		TTL: s.TTL, Data: fqdn,
	}}
	return s.reply(req, q, dnsmsg.RcodeNoError, answers, nil)
}

func (s *Server) reply(req []byte, q dnsmsg.Question, rcode int, answers, authority []dnsmsg.ResourceRecord) []byte {
	resp, err := dnsmsg.BuildReply(req, q, dnsmsg.FlagAA|dnsmsg.FlagRA, rcode, answers, authority)
	if err != nil {
		s.Log.Debug("building reply failed", "error", err)
		return nil
	}
	return resp
}

func (s *Server) soaRecord() dnsmsg.ResourceRecord {
	owner, _ := dnsmsg.EncodeName(s.Domain)
	data, _ := dnsmsg.SOAData(
		"ns."+s.Domain, "hostmaster."+s.Domain,
		uint32(time.Now().Unix()), 3600, 600, 86400, s.TTL,
	)
	return dnsmsg.ResourceRecord{
		Name: owner, Type: dnsmsg.TypeSOA, Class: dnsmsg.ClassIN,
		TTL: s.TTL, Data: data,
	}
}

// forward relays the raw query to the upstream resolvers over the same
// transport the client used and returns the raw answer.
func (s *Server) forward(req []byte, transport string, q dnsmsg.Question, haveQ bool) []byte {
	for _, up := range s.Upstreams {
		var (
			resp []byte
			err  error
		)
		if transport == "udp" {
			resp, err = exchangeUDP(up, req)
		} else {
			resp, err = exchangeTCP(up, req)
		}
		if err == nil {
			return resp
		}
		s.Log.Debug("upstream failed", "upstream", up, "error", err)
	}
	s.Log.Warn("all upstreams failed", "name", q.Name, "transport", transport)
	if haveQ {
		if resp := s.replyServFail(req, q); resp != nil {
			return resp
		}
	}
	if h, err := dnsmsg.ParseHeader(req); err == nil {
		return dnsmsg.BuildHeaderOnly(h.ID, h.Flags, dnsmsg.RcodeServFail)
	}
	return nil
}

func (s *Server) replyServFail(req []byte, q dnsmsg.Question) []byte {
	resp, err := dnsmsg.BuildReply(req, q, dnsmsg.FlagRA, dnsmsg.RcodeServFail, nil, nil)
	if err != nil {
		return nil
	}
	return resp
}

func exchangeUDP(upstream string, req []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", upstream, udpTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(udpTimeout))
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	buf := make([]byte, maxTCPMsg) // EDNS answers can exceed 512 bytes
	for attempt := 0; attempt < 3; attempt++ {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n >= 2 && buf[0] == req[0] && buf[1] == req[1] {
			return buf[:n], nil
		}
	}
	return nil, errors.New("no matching response")
}

func exchangeTCP(upstream string, req []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", upstream, tcpTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(tcpTimeout))
	if err := writeTCPMsg(conn, req); err != nil {
		return nil, err
	}
	return readTCPMsg(conn)
}

func readTCPMsg(conn net.Conn) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	msgLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if msgLen == 0 {
		return nil, errors.New("zero-length message")
	}
	msg := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func writeTCPMsg(conn net.Conn, msg []byte) error {
	if len(msg) > maxTCPMsg {
		return errors.New("message too large")
	}
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out[:2], uint16(len(msg)))
	copy(out[2:], msg)
	_, err := conn.Write(out)
	return err
}
