package scanner

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/okmtdev/local-dns/internal/dnsmsg"
)

func encodeNameForTest(t *testing.T, name string) []byte {
	t.Helper()
	wire, err := dnsmsg.EncodeName(name)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestParseARPTable(t *testing.T) {
	sample := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         a4:12:42:aa:bb:01     *        eth0
192.168.1.23     0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.1.50     0x1         0x2         F8:4D:89:CC:DD:02     *        eth0
192.168.1.60     0x1         0x6         11:22:33:44:55:66     *        wlan0
10.8.0.2         0x20        0x2         de:ad:be:ef:00:01     *        tun0
`
	got := parseARPTable(strings.NewReader(sample))
	if len(got) != 3 {
		t.Fatalf("entries = %d, want 3 (%+v)", len(got), got)
	}
	if got[0].IP != "192.168.1.1" || got[0].MAC != "a4:12:42:aa:bb:01" || got[0].Dev != "eth0" {
		t.Errorf("entry 0 = %+v", got[0])
	}
	if got[1].MAC != "f8:4d:89:cc:dd:02" {
		t.Errorf("entry 1 MAC not lowercased: %+v", got[1])
	}
	if got[2].Dev != "wlan0" {
		t.Errorf("entry 2 = %+v", got[2])
	}
}

func TestHostsInSubnet(t *testing.T) {
	_, ipn, _ := net.ParseCIDR("192.168.1.0/29")
	hosts := hostsInSubnet(ipn, 4096)
	if len(hosts) != 6 {
		t.Fatalf("/29 hosts = %d, want 6", len(hosts))
	}
	if hosts[0].String() != "192.168.1.1" || hosts[5].String() != "192.168.1.6" {
		t.Errorf("range = %s .. %s", hosts[0], hosts[5])
	}

	_, ipn24, _ := net.ParseCIDR("10.0.0.0/24")
	if got := len(hostsInSubnet(ipn24, 4096)); got != 254 {
		t.Errorf("/24 hosts = %d, want 254", got)
	}

	_, ipn31, _ := net.ParseCIDR("10.0.0.0/31")
	if got := len(hostsInSubnet(ipn31, 4096)); got != 2 {
		t.Errorf("/31 hosts = %d, want 2", got)
	}

	_, big, _ := net.ParseCIDR("10.0.0.0/16")
	if hostsInSubnet(big, 4096) != nil {
		t.Error("/16 should exceed the cap")
	}

	// Non-aligned IP inside the CIDR must still enumerate from the base.
	_, ipn2, _ := net.ParseCIDR("192.168.1.130/25")
	hosts = hostsInSubnet(ipn2, 4096)
	if len(hosts) != 126 || hosts[0].String() != "192.168.1.129" {
		t.Errorf("/25 = %d hosts, first %s", len(hosts), hosts[0])
	}
}

func TestDefaultRouteIface(t *testing.T) {
	content := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth1\t00000A0A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n" +
		"eth0\t00000000\t010F02C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
	path := filepath.Join(t.TempDir(), "route")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	iface, err := defaultRouteIface(path)
	if err != nil || iface != "eth0" {
		t.Errorf("defaultRouteIface = %q, %v", iface, err)
	}
}

func TestOUIParsing(t *testing.T) {
	dir := t.TempDir()

	ieee := filepath.Join(dir, "oui.txt")
	os.WriteFile(ieee, []byte(
		"OUI/MA-L\t\t\tOrganization\n"+
			"28-6F-B9   (hex)\t\tNokia Shanghai Bell Co., Ltd.\n"+
			"286FB9     (base 16)\t\tNokia Shanghai Bell Co., Ltd.\n"+
			"\t\t\tBuilding 1, No.388 Ningqiao Road\n"+
			"F8-4D-89   (hex)\t\tApple, Inc.\n"), 0o644)

	nmap := filepath.Join(dir, "nmap-mac-prefixes")
	os.WriteFile(nmap, []byte(
		"# comment\n"+
			"E89F6D Espressif\n"), 0o644)

	manuf := filepath.Join(dir, "manuf")
	os.WriteFile(manuf, []byte(
		"# Wireshark manuf\n"+
			"00:00:0C\tCisco\tCisco Systems, Inc\n"+
			"00:50:C2:00:00:00/36\tShort\tBlock entry skipped\n"), 0o644)

	table := LoadOUI([]string{ieee, nmap, manuf, filepath.Join(dir, "missing")})
	if table.Len() < 4 {
		t.Fatalf("Len = %d, want >= 4", table.Len())
	}
	cases := map[string]string{
		"28:6f:b9:11:22:33": "Nokia Shanghai Bell Co., Ltd.",
		"f8:4d:89:aa:bb:cc": "Apple, Inc.",
		"e8:9f:6d:00:00:01": "Espressif",
		"00:00:0c:99:99:99": "Cisco Systems, Inc",
		"ff:ff:ff:00:00:00": "",
	}
	for mac, want := range cases {
		if got := table.Lookup(mac); got != want {
			t.Errorf("Lookup(%q) = %q, want %q", mac, got, want)
		}
	}
	var nilTable *OUITable
	if nilTable.Lookup("28:6f:b9:11:22:33") != "" || nilTable.Len() != 0 {
		t.Error("nil table should be a safe no-op")
	}
}

func TestParseNBNSReply(t *testing.T) {
	// Craft a minimal node-status response: header, no questions, one
	// answer with two names (a group name, then a unique one).
	msg := make([]byte, 0, 128)
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], 0x1D7E)
	hdr[2] = 0x84 // response
	binary.BigEndian.PutUint16(hdr[6:8], 1)
	msg = append(msg, hdr...)
	// answer name: 32-byte encoded name
	msg = append(msg, 0x20)
	msg = append(msg, []byte("CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")...)
	msg = append(msg, 0x00)
	msg = append(msg, 0x00, 0x21) // NBSTAT
	msg = append(msg, 0x00, 0x01) // IN
	msg = append(msg, 0, 0, 0, 0) // TTL
	// RDATA
	rdata := []byte{2} // number of names
	group := append([]byte("WORKGROUP      "), 0x00, 0x84, 0x00)
	unique := append([]byte("DESKTOP-AB12   "), 0x00, 0x04, 0x00)
	rdata = append(rdata, group...)
	rdata = append(rdata, unique...)
	msg = append(msg, 0, byte(len(rdata)))
	msg = append(msg, rdata...)

	got := parseNBNSReply(msg)
	if got != "DESKTOP-AB12" {
		t.Errorf("parseNBNSReply = %q, want DESKTOP-AB12", got)
	}

	if parseNBNSReply(msg[:20]) != "" {
		t.Error("truncated reply should yield empty result")
	}
	if parseNBNSReply(nil) != "" {
		t.Error("nil reply should yield empty result")
	}
}

func TestNBNSQueryShape(t *testing.T) {
	q := nbnsQuery()
	if len(q) != 50 {
		t.Fatalf("query length = %d, want 50", len(q))
	}
	if q[12] != 0x20 || q[13] != 'C' || q[14] != 'K' || q[45] != 0x00 {
		t.Errorf("encoded name wrong: % x", q[12:46])
	}
	if binary.BigEndian.Uint16(q[46:48]) != 0x0021 {
		t.Error("qtype != NBSTAT")
	}
}

func TestExtractMDNSPtr(t *testing.T) {
	// Build an mDNS response for 10.1.168.192.in-addr.arpa -> host.local.
	qname := "10.1.168.192.in-addr.arpa"
	msg := make([]byte, 0, 128)
	hdr := make([]byte, 12)
	hdr[2] = 0x84 // QR|AA
	binary.BigEndian.PutUint16(hdr[6:8], 1)
	msg = append(msg, hdr...)
	name := encodeNameForTest(t, qname)
	msg = append(msg, name...)
	msg = append(msg, 0x00, 0x0C)             // PTR
	msg = append(msg, 0x80, 0x01)             // cache-flush | IN
	msg = append(msg, 0x00, 0x00, 0x00, 0x78) // TTL
	target := encodeNameForTest(t, "Living-Room-TV.local")
	msg = append(msg, 0x00, byte(len(target)))
	msg = append(msg, target...)

	if got := extractMDNSPtr(msg, qname); got != "living-room-tv" {
		t.Errorf("extractMDNSPtr = %q, want living-room-tv", got)
	}
	if got := extractMDNSPtr(msg, "other.in-addr.arpa"); got != "" {
		t.Errorf("wrong qname matched: %q", got)
	}
}

func TestParseV4(t *testing.T) {
	if parseV4("192.168.1.1") == nil || parseV4("::1") != nil || parseV4("junk") != nil {
		t.Error("parseV4 misbehaves")
	}
}
