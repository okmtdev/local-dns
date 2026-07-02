package dnsmsg

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func mustEncode(t *testing.T, name string) []byte {
	t.Helper()
	wire, err := EncodeName(name)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestBuildQueryParseQuestion(t *testing.T) {
	q, err := BuildQuery(0xBEEF, "NAS.Home.Arpa", TypeA, ClassIN, true)
	if err != nil {
		t.Fatal(err)
	}
	h, err := ParseHeader(q)
	if err != nil {
		t.Fatal(err)
	}
	if h.ID != 0xBEEF || h.QDCount != 1 || h.Flags&FlagRD == 0 || h.Response() {
		t.Errorf("header = %+v", h)
	}
	parsed, err := ParseQuestion(q)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Name != "nas.home.arpa" || parsed.Type != TypeA || parsed.Class != ClassIN {
		t.Errorf("question = %+v", parsed)
	}
	if parsed.End != len(q) {
		t.Errorf("End = %d, want %d", parsed.End, len(q))
	}
}

func TestParseQuestionRejectsCompression(t *testing.T) {
	q, _ := BuildQuery(1, "a.b", TypeA, ClassIN, false)
	q[12] = 0xC0 // pretend the name starts with a pointer
	if _, err := ParseQuestion(q); err == nil {
		t.Error("expected error for compressed question name")
	}
}

func TestParseQuestionTruncated(t *testing.T) {
	q, _ := BuildQuery(1, "abc", TypeA, ClassIN, false)
	for i := 1; i < len(q); i++ {
		if _, err := ParseQuestion(q[:i]); err == nil {
			t.Errorf("expected error at length %d", i)
		}
	}
}

func TestBuildReplyRoundTrip(t *testing.T) {
	req, _ := BuildQuery(0x1234, "nas.home.arpa", TypeA, ClassIN, true)
	q, _ := ParseQuestion(req)

	soa, err := SOAData("ns.home.arpa", "hostmaster.home.arpa", 42, 3600, 600, 86400, 30)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := BuildReply(req, q, FlagAA|FlagRA, RcodeNoError,
		[]ResourceRecord{{
			Name: NamePtr(12), Type: TypeA, Class: ClassIN, TTL: 30,
			Data: []byte{192, 168, 1, 50},
		}},
		[]ResourceRecord{{
			Name: mustEncode(t, "home.arpa"), Type: TypeSOA, Class: ClassIN, TTL: 30,
			Data: soa,
		}},
	)
	if err != nil {
		t.Fatal(err)
	}

	h, questions, rrs, err := ParseMessage(resp)
	if err != nil {
		t.Fatal(err)
	}
	if h.ID != 0x1234 || !h.Response() || h.Flags&FlagAA == 0 || h.Flags&FlagRA == 0 || h.Flags&FlagRD == 0 {
		t.Errorf("header = %+v", h)
	}
	if h.Rcode() != RcodeNoError || h.ANCount != 1 || h.NSCount != 1 {
		t.Errorf("counts/rcode = %+v", h)
	}
	if len(questions) != 1 || questions[0].Name != "nas.home.arpa" {
		t.Errorf("questions = %+v", questions)
	}
	if len(rrs) != 2 {
		t.Fatalf("rrs = %+v", rrs)
	}
	a := rrs[0]
	if a.Name != "nas.home.arpa" || a.Type != TypeA || a.TTL != 30 || a.Section != 0 {
		t.Errorf("answer rr = %+v", a)
	}
	if !bytes.Equal(resp[a.DataStart:a.DataStart+a.DataLen], []byte{192, 168, 1, 50}) {
		t.Errorf("A rdata = %v", resp[a.DataStart:a.DataStart+a.DataLen])
	}
	if rrs[1].Name != "home.arpa" || rrs[1].Type != TypeSOA || rrs[1].Section != 1 {
		t.Errorf("soa rr = %+v", rrs[1])
	}
}

func TestBuildHeaderOnly(t *testing.T) {
	resp := BuildHeaderOnly(7, FlagRD, RcodeServFail)
	h, err := ParseHeader(resp)
	if err != nil {
		t.Fatal(err)
	}
	if h.ID != 7 || !h.Response() || h.Rcode() != RcodeServFail || h.QDCount != 0 {
		t.Errorf("header = %+v", h)
	}
}

func TestEncodeNameErrors(t *testing.T) {
	if _, err := EncodeName("a..b"); err == nil {
		t.Error("expected error for empty label")
	}
	long := make([]byte, 70)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := EncodeName(string(long)); err == nil {
		t.Error("expected error for oversized label")
	}
	root, err := EncodeName("")
	if err != nil || !bytes.Equal(root, []byte{0}) {
		t.Errorf("root = %v, %v", root, err)
	}
}

func TestDecodeNameCompression(t *testing.T) {
	// Build a message manually: question "host.example" plus an answer
	// whose name is a pointer and whose RDATA points into the question.
	msg := make([]byte, 0, 64)
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[4:6], 1) // QDCOUNT
	binary.BigEndian.PutUint16(hdr[6:8], 1) // ANCOUNT
	hdr[2] = 0x80                           // QR
	msg = append(msg, hdr[:]...)
	name, _ := EncodeName("host.example")
	msg = append(msg, name...)
	msg = append(msg, 0, 12, 0, 1) // PTR IN
	// answer: name = pointer to offset 12
	msg = append(msg, 0xC0, 12)
	msg = append(msg, 0, 12, 0, 1) // TYPE PTR, CLASS IN
	msg = append(msg, 0, 0, 0, 30) // TTL
	// RDATA: "target." + pointer to "example" (offset 12+5=17)
	rdata := []byte{6, 't', 'a', 'r', 'g', 'e', 't', 0xC0, 17}
	msg = append(msg, 0, byte(len(rdata)))
	msg = append(msg, rdata...)

	_, qs, rrs, err := ParseMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	if qs[0].Name != "host.example" {
		t.Errorf("question = %q", qs[0].Name)
	}
	if len(rrs) != 1 || rrs[0].Name != "host.example" {
		t.Fatalf("rrs = %+v", rrs)
	}
	target, err := DecodeNameAt(msg, rrs[0].DataStart)
	if err != nil || target != "target.example" {
		t.Errorf("target = %q, %v", target, err)
	}
}

func TestDecodeNamePointerLoop(t *testing.T) {
	msg := make([]byte, 14)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	msg[12] = 0xC0
	msg[13] = 12 // points at itself
	if _, _, _, err := ParseMessage(msg); err == nil {
		t.Error("expected error for pointer loop")
	}
}

func TestReverseName(t *testing.T) {
	got := ReverseName([]byte{192, 168, 1, 50})
	if got != "50.1.168.192.in-addr.arpa" {
		t.Errorf("ReverseName = %q", got)
	}
	ip := ParseReverseName("50.1.168.192.in-addr.arpa")
	if ip == nil || ip[0] != 192 || ip[1] != 168 || ip[2] != 1 || ip[3] != 50 {
		t.Errorf("ParseReverseName = %v", ip)
	}
	for _, bad := range []string{
		"1.168.192.in-addr.arpa", "a.1.168.192.in-addr.arpa",
		"256.1.168.192.in-addr.arpa", "nas.home.arpa", "50.1.168.192.ip6.arpa",
	} {
		if ip := ParseReverseName(bad); ip != nil {
			t.Errorf("ParseReverseName(%q) = %v, want nil", bad, ip)
		}
	}
}
