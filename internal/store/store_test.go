package store

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "state.json"), 90*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestApplyScanAndDevices(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()

	material := s.ApplyScan([]SeenDevice{
		{MAC: "AA:BB:CC:DD:EE:01", IP: "192.168.1.10"},
		{MAC: "aa:bb:cc:dd:ee:02", IP: "192.168.1.2"},
		{MAC: "bogus", IP: "192.168.1.99"}, // ignored
	}, now)
	if !material {
		t.Error("first scan should be material")
	}

	devices := s.Devices(now)
	if len(devices) != 2 {
		t.Fatalf("devices = %d, want 2", len(devices))
	}
	// Sorted by IP: .2 before .10.
	if devices[0].IP != "192.168.1.2" || devices[1].IP != "192.168.1.10" {
		t.Errorf("order = %s, %s", devices[0].IP, devices[1].IP)
	}
	if devices[0].MAC != "aa:bb:cc:dd:ee:02" {
		t.Errorf("MAC = %q", devices[0].MAC)
	}
	if !devices[0].Online {
		t.Error("freshly seen device should be online")
	}

	// Same scan again: not material.
	if s.ApplyScan([]SeenDevice{{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.1.10"}}, now.Add(time.Second)) {
		t.Error("unchanged scan should not be material")
	}
	// IP change: material.
	if !s.ApplyScan([]SeenDevice{{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.1.11"}}, now.Add(2*time.Second)) {
		t.Error("IP change should be material")
	}

	// Online window.
	later := now.Add(10 * time.Minute)
	for _, d := range s.Devices(later) {
		if d.Online {
			t.Errorf("device %s should be offline after 10min", d.MAC)
		}
	}
}

func TestMappingsAndResolve(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	s.ApplyScan([]SeenDevice{{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.1.10"}}, now)

	if _, err := s.SetMapping("NAS.", "aa:bb:cc:dd:ee:01", "", "my nas"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetMapping("printer", "", "192.168.1.200", ""); err != nil {
		t.Fatal(err)
	}

	// Validation errors.
	if _, err := s.SetMapping("bad name!", "aa:bb:cc:dd:ee:01", "", ""); err == nil {
		t.Error("invalid hostname accepted")
	}
	if _, err := s.SetMapping("x", "", "", ""); err == nil {
		t.Error("no target accepted")
	}
	if _, err := s.SetMapping("x", "aa:bb:cc:dd:ee:01", "192.168.1.5", ""); err == nil {
		t.Error("two targets accepted")
	}
	if _, err := s.SetMapping("x", "nope", "", ""); err == nil {
		t.Error("bad MAC accepted")
	}
	if _, err := s.SetMapping("x", "", "999.1.1.1", ""); err == nil {
		t.Error("bad IP accepted")
	}

	ip, found := s.ResolveName("nas")
	if !found || !ip.Equal(net.ParseIP("192.168.1.10")) {
		t.Errorf("nas -> %v, %v", ip, found)
	}
	ip, found = s.ResolveName("printer")
	if !found || !ip.Equal(net.ParseIP("192.168.1.200")) {
		t.Errorf("printer -> %v, %v", ip, found)
	}
	if _, found := s.ResolveName("nothere"); found {
		t.Error("unknown name resolved")
	}

	// Device IP moves -> resolution follows.
	s.ApplyScan([]SeenDevice{{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.1.42"}}, now.Add(time.Second))
	ip, _ = s.ResolveName("nas")
	if !ip.Equal(net.ParseIP("192.168.1.42")) {
		t.Errorf("nas after move -> %v", ip)
	}

	// PTR.
	host, ok := s.ResolvePTR(net.ParseIP("192.168.1.42"))
	if !ok || host != "nas" {
		t.Errorf("PTR = %q, %v", host, ok)
	}
	if _, ok := s.ResolvePTR(net.ParseIP("10.0.0.1")); ok {
		t.Error("unknown PTR resolved")
	}

	// Mapping to a never-seen device: found but nil IP (NODATA).
	if _, err := s.SetMapping("ghost", "aa:bb:cc:dd:ee:99", "", ""); err != nil {
		t.Fatal(err)
	}
	ip, found = s.ResolveName("ghost")
	if !found || ip != nil {
		t.Errorf("ghost -> %v, %v; want nil, true", ip, found)
	}

	// Views.
	views := s.Mappings(now.Add(2 * time.Second))
	if len(views) != 3 {
		t.Fatalf("mappings = %d", len(views))
	}
	byName := map[string]MappingView{}
	for _, v := range views {
		byName[v.Hostname] = v
	}
	if byName["nas"].CurrentIP != "192.168.1.42" || !byName["nas"].Online {
		t.Errorf("nas view = %+v", byName["nas"])
	}
	if !byName["printer"].Online || byName["printer"].CurrentIP != "192.168.1.200" {
		t.Errorf("printer view = %+v", byName["printer"])
	}
	if byName["ghost"].Online {
		t.Errorf("ghost view = %+v", byName["ghost"])
	}

	// Device view includes names.
	dv := s.Devices(now.Add(2 * time.Second))
	if len(dv[0].Names) != 1 || dv[0].Names[0] != "nas" {
		t.Errorf("device names = %v", dv[0].Names)
	}

	// Delete.
	existed, err := s.DeleteMapping("printer")
	if err != nil || !existed {
		t.Errorf("DeleteMapping = %v, %v", existed, err)
	}
	existed, err = s.DeleteMapping("printer")
	if err != nil || existed {
		t.Errorf("second DeleteMapping = %v, %v", existed, err)
	}
}

func TestUpdateMapping(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	s.ApplyScan([]SeenDevice{{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.1.10"}}, now)

	created, err := s.SetMapping("nas", "aa:bb:cc:dd:ee:01", "", "old note")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetMapping("printer", "", "192.168.1.200", ""); err != nil {
		t.Fatal(err)
	}

	// Update in place (target + note change, MAC -> static IP).
	m, err := s.UpdateMapping("nas", "nas", "", "192.168.1.99", "new note")
	if err != nil {
		t.Fatal(err)
	}
	if m.IP != "192.168.1.99" || m.MAC != "" || m.Note != "new note" {
		t.Errorf("updated = %+v", m)
	}
	if !m.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("CreatedAt changed: %v -> %v", created.CreatedAt, m.CreatedAt)
	}

	// Rename.
	m, err = s.UpdateMapping("nas", "storage", "aa:bb:cc:dd:ee:01", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if m.Hostname != "storage" {
		t.Errorf("renamed = %+v", m)
	}
	if _, found := s.ResolveName("nas"); found {
		t.Error("old name still resolves after rename")
	}
	if ip, found := s.ResolveName("storage"); !found || !ip.Equal(net.ParseIP("192.168.1.10")) {
		t.Errorf("storage -> %v, %v", ip, found)
	}

	// Rename onto a taken name fails and changes nothing.
	if _, err := s.UpdateMapping("storage", "printer", "aa:bb:cc:dd:ee:01", "", ""); err == nil {
		t.Error("rename onto taken hostname accepted")
	}
	if _, found := s.ResolveName("storage"); !found {
		t.Error("failed rename must keep the original mapping")
	}

	// Unknown mapping -> ErrMappingNotFound.
	if _, err := s.UpdateMapping("ghost", "ghost2", "", "1.2.3.4", ""); !errors.Is(err, ErrMappingNotFound) {
		t.Errorf("update unknown = %v, want ErrMappingNotFound", err)
	}

	// Validation still applies.
	if _, err := s.UpdateMapping("storage", "Bad Name", "", "1.2.3.4", ""); err == nil {
		t.Error("invalid new hostname accepted")
	}
	if _, err := s.UpdateMapping("storage", "storage", "", "", ""); err == nil {
		t.Error("missing target accepted")
	}

	// Persistence: rename survives a reload.
	s2, err := Open(s.path, 90*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := s2.ResolveName("storage"); !found {
		t.Error("renamed mapping missing after reload")
	}
}

func TestLabelsAndDeleteDevice(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	s.ApplyScan([]SeenDevice{{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.1.10"}}, now)

	if err := s.SetLabel("AA:BB:CC:DD:EE:01", "リビングTV"); err != nil {
		t.Fatal(err)
	}
	d, ok := s.Device("aa:bb:cc:dd:ee:01")
	if !ok || d.Label != "リビングTV" {
		t.Errorf("device = %+v", d)
	}
	if err := s.SetLabel("aa:bb:cc:dd:ee:99", "x"); err == nil {
		t.Error("label on unknown device accepted")
	}
	if err := s.DeleteDevice("aa:bb:cc:dd:ee:01"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDevice("aa:bb:cc:dd:ee:01"); err == nil {
		t.Error("second delete should fail")
	}
}

func TestHostnameVendorUpdates(t *testing.T) {
	s := newTestStore(t)
	s.ApplyScan([]SeenDevice{{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.1.10"}}, time.Now())

	if !s.SetDiscoveredHostname("aa:bb:cc:dd:ee:01", "MacBook-Pro") {
		t.Error("first hostname set should report change")
	}
	if s.SetDiscoveredHostname("aa:bb:cc:dd:ee:01", "MacBook-Pro") {
		t.Error("same hostname should not report change")
	}
	if s.SetDiscoveredHostname("aa:bb:cc:dd:ee:99", "ghost") {
		t.Error("unknown device should not report change")
	}
	if !s.SetVendor("aa:bb:cc:dd:ee:01", "Apple, Inc.") {
		t.Error("vendor set should report change")
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	now := time.Now()

	s1, err := Open(path, 90*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	s1.ApplyScan([]SeenDevice{{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.1.10", Self: true}}, now)
	s1.SetDiscoveredHostname("aa:bb:cc:dd:ee:01", "server")
	if _, err := s1.SetMapping("nas", "aa:bb:cc:dd:ee:01", "", "note"); err != nil {
		t.Fatal(err)
	}
	if err := s1.Save(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(path, 90*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	d, ok := s2.Device("aa:bb:cc:dd:ee:01")
	if !ok || d.IP != "192.168.1.10" || d.Hostname != "server" || !d.Self {
		t.Errorf("reloaded device = %+v", d)
	}
	ip, found := s2.ResolveName("nas")
	if !found || !ip.Equal(net.ParseIP("192.168.1.10")) {
		t.Errorf("reloaded nas -> %v, %v", ip, found)
	}

	// SaveIfDirty right after a clean load is a no-op and must not fail.
	if err := s2.SaveIfDirty(); err != nil {
		t.Fatal(err)
	}
}

func TestCorruptStateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(path, time.Minute)
	if !errors.Is(err, ErrCorrupt) {
		t.Errorf("Open corrupt = %v, want ErrCorrupt", err)
	}
}

func TestCounts(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	s.ApplyScan([]SeenDevice{
		{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.1.10"},
		{MAC: "aa:bb:cc:dd:ee:02", IP: "192.168.1.11"},
	}, now.Add(-10*time.Minute))
	s.ApplyScan([]SeenDevice{{MAC: "aa:bb:cc:dd:ee:02", IP: "192.168.1.11"}}, now)
	total, online := s.Counts(now)
	if total != 2 || online != 1 {
		t.Errorf("Counts = %d/%d, want 2/1", total, online)
	}
}
