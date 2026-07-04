package web

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/okmtdev/local-dns/internal/store"
)

type fakeScanner struct {
	triggered int
	last      time.Time
}

func (f *fakeScanner) Trigger()            { f.triggered++ }
func (f *fakeScanner) LastScan() time.Time { return f.last }

func newTestServer(t *testing.T, username, password string) (*httptest.Server, *store.Store, *fakeScanner) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.json"), 90*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sc := &fakeScanner{last: time.Now()}
	srv := &Server{
		Store:   st,
		Scanner: sc,
		Info: Info{
			Version:      "test",
			Domain:       "home.arpa",
			DNSListen:    ":53",
			TTL:          30,
			ScanInterval: 30 * time.Second,
			Upstreams:    []string{"1.1.1.1:53"},
		},
		Username: username,
		Password: password,
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, st, sc
}

func doJSON(t *testing.T, method, url string, body any) (*http.Response, map[string]any) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var decoded map[string]any
	data, _ := io.ReadAll(res.Body)
	if len(data) > 0 && data[0] == '{' {
		json.Unmarshal(data, &decoded)
	}
	return res, decoded
}

func TestStatusAndIndex(t *testing.T) {
	ts, _, _ := newTestServer(t, "", "")

	res, body := doJSON(t, "GET", ts.URL+"/api/status", nil)
	if res.StatusCode != 200 {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if body["domain"] != "home.arpa" || body["version"] != "test" {
		t.Errorf("status body = %v", body)
	}

	res2, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	html, _ := io.ReadAll(res2.Body)
	if res2.StatusCode != 200 || !strings.Contains(string(html), "local-dns") {
		t.Errorf("index = %d, %.60s", res2.StatusCode, html)
	}
	if ct := res2.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content type = %q", ct)
	}

	res3, err := http.Get(ts.URL + "/static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	res3.Body.Close()
	if res3.StatusCode != 200 {
		t.Errorf("app.js = %d", res3.StatusCode)
	}

	res4, err := http.Get(ts.URL + "/no-such-page")
	if err != nil {
		t.Fatal(err)
	}
	res4.Body.Close()
	if res4.StatusCode != 404 {
		t.Errorf("unknown page = %d, want 404", res4.StatusCode)
	}
}

func TestDeviceAndMappingFlow(t *testing.T) {
	ts, st, _ := newTestServer(t, "", "")
	now := time.Now()
	st.ApplyScan([]store.SeenDevice{
		{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.1.10"},
	}, now)
	st.SetDiscoveredHostname("aa:bb:cc:dd:ee:01", "macbook")

	// Devices list.
	res, err := http.Get(ts.URL + "/api/devices")
	if err != nil {
		t.Fatal(err)
	}
	var devices []map[string]any
	json.NewDecoder(res.Body).Decode(&devices)
	res.Body.Close()
	if len(devices) != 1 || devices[0]["display_name"] != "macbook" || devices[0]["online"] != true {
		t.Fatalf("devices = %v", devices)
	}

	// Create a mapping for the device.
	res, body := doJSON(t, "POST", ts.URL+"/api/mappings", map[string]string{
		"hostname": "Mac", "mac": "AA:BB:CC:DD:EE:01", "note": "テスト",
	})
	if res.StatusCode != 200 {
		t.Fatalf("post mapping = %d %v", res.StatusCode, body)
	}

	// Invalid mapping is rejected.
	res, body = doJSON(t, "POST", ts.URL+"/api/mappings", map[string]string{
		"hostname": "bad name", "mac": "aa:bb:cc:dd:ee:01",
	})
	if res.StatusCode != 400 || body["error"] == "" {
		t.Errorf("invalid mapping = %d %v", res.StatusCode, body)
	}

	// Mappings list shows the resolved IP and FQDN.
	res, err = http.Get(ts.URL + "/api/mappings")
	if err != nil {
		t.Fatal(err)
	}
	var mappings []map[string]any
	json.NewDecoder(res.Body).Decode(&mappings)
	res.Body.Close()
	if len(mappings) != 1 {
		t.Fatalf("mappings = %v", mappings)
	}
	m := mappings[0]
	if m["fqdn"] != "mac.home.arpa" || m["current_ip"] != "192.168.1.10" || m["online"] != true {
		t.Errorf("mapping = %v", m)
	}

	// Device now shows the name.
	res, err = http.Get(ts.URL + "/api/devices")
	if err != nil {
		t.Fatal(err)
	}
	json.NewDecoder(res.Body).Decode(&devices)
	res.Body.Close()
	names := devices[0]["names"].([]any)
	if len(names) != 1 || names[0].(map[string]any)["fqdn"] != "mac.home.arpa" {
		t.Errorf("device names = %v", names)
	}

	// Label the device.
	res, _ = doJSON(t, "PATCH", ts.URL+"/api/devices/aa:bb:cc:dd:ee:01", map[string]string{"label": "ノートPC"})
	if res.StatusCode != 200 {
		t.Errorf("patch label = %d", res.StatusCode)
	}
	d, _ := st.Device("aa:bb:cc:dd:ee:01")
	if d.Label != "ノートPC" {
		t.Errorf("label = %q", d.Label)
	}

	// Delete mapping (URL-escaped hostname).
	res, _ = doJSON(t, "DELETE", ts.URL+"/api/mappings/mac", nil)
	if res.StatusCode != 200 {
		t.Errorf("delete mapping = %d", res.StatusCode)
	}
	res, _ = doJSON(t, "DELETE", ts.URL+"/api/mappings/mac", nil)
	if res.StatusCode != 404 {
		t.Errorf("delete missing mapping = %d, want 404", res.StatusCode)
	}

	// Delete device.
	res, _ = doJSON(t, "DELETE", ts.URL+"/api/devices/aa:bb:cc:dd:ee:01", nil)
	if res.StatusCode != 200 {
		t.Errorf("delete device = %d", res.StatusCode)
	}
}

func TestUpdateMappingAPI(t *testing.T) {
	ts, st, _ := newTestServer(t, "", "")
	st.ApplyScan([]store.SeenDevice{
		{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.1.10"},
	}, time.Now())
	if _, err := st.SetMapping("nas", "aa:bb:cc:dd:ee:01", "", "before"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetMapping("printer", "", "192.168.1.200", ""); err != nil {
		t.Fatal(err)
	}

	// Rename + retarget + note change in one call.
	res, body := doJSON(t, "PUT", ts.URL+"/api/mappings/nas", map[string]string{
		"hostname": "Storage", "ip": "192.168.1.99", "note": "after",
	})
	if res.StatusCode != 200 {
		t.Fatalf("put = %d %v", res.StatusCode, body)
	}
	if body["hostname"] != "storage" || body["ip"] != "192.168.1.99" || body["note"] != "after" {
		t.Errorf("updated mapping = %v", body)
	}
	if _, found := st.ResolveName("nas"); found {
		t.Error("old hostname still resolves")
	}

	// Updating a missing mapping is a 404.
	res, _ = doJSON(t, "PUT", ts.URL+"/api/mappings/nas", map[string]string{
		"hostname": "nas", "ip": "192.168.1.99",
	})
	if res.StatusCode != 404 {
		t.Errorf("put missing = %d, want 404", res.StatusCode)
	}

	// Renaming onto a taken hostname is a 400.
	res, body = doJSON(t, "PUT", ts.URL+"/api/mappings/storage", map[string]string{
		"hostname": "printer", "ip": "192.168.1.99",
	})
	if res.StatusCode != 400 || body["error"] == "" {
		t.Errorf("conflicting rename = %d %v", res.StatusCode, body)
	}
}

func TestScanTrigger(t *testing.T) {
	ts, _, sc := newTestServer(t, "", "")
	res, body := doJSON(t, "POST", ts.URL+"/api/scan", nil)
	if res.StatusCode != 202 || body["status"] != "scanning" {
		t.Errorf("scan = %d %v", res.StatusCode, body)
	}
	if sc.triggered != 1 {
		t.Errorf("triggered = %d", sc.triggered)
	}
}

func TestBasicAuth(t *testing.T) {
	ts, _, _ := newTestServer(t, "admin", "secret")

	res, err := http.Get(ts.URL + "/api/status")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatalf("no-auth = %d, want 401", res.StatusCode)
	}
	if res.Header.Get("WWW-Authenticate") == "" {
		t.Error("missing WWW-Authenticate header")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/status", nil)
	req.SetBasicAuth("admin", "wrong")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Errorf("bad password = %d, want 401", res.StatusCode)
	}

	req, _ = http.NewRequest("GET", ts.URL+"/api/status", nil)
	req.SetBasicAuth("admin", "secret")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Errorf("good auth = %d, want 200", res.StatusCode)
	}
}
