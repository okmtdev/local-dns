package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.conf")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	cfg, found, err := Load(filepath.Join(t.TempDir(), "nope.conf"))
	if err != nil || found {
		t.Fatalf("Load missing = found %v, err %v", found, err)
	}
	def := Default()
	if !reflect.DeepEqual(cfg, def) {
		t.Errorf("got %+v, want defaults %+v", cfg, def)
	}
}

func TestLoadFullConfig(t *testing.T) {
	path := writeTemp(t, `
# comment
domain: Lan.
dns_listen: :5353
web_listen: 127.0.0.1:9090
upstreams: 192.168.1.1, 2001:db8::1, 9.9.9.9:9953
ttl: 60
scan_interval: 1m
scan_cidr: 192.168.10.0/24
scan_interface: eth1
disable_sweep: yes
state_path: /tmp/state.json
web_username: admin
web_password: secret
answer_single_label: false
log_level: DEBUG
`)
	cfg, found, err := Load(path)
	if err != nil || !found {
		t.Fatalf("Load = found %v, err %v", found, err)
	}
	if cfg.Domain != "lan" {
		t.Errorf("Domain = %q", cfg.Domain)
	}
	wantUp := []string{"192.168.1.1:53", "[2001:db8::1]:53", "9.9.9.9:9953"}
	if !reflect.DeepEqual(cfg.Upstreams, wantUp) {
		t.Errorf("Upstreams = %v, want %v", cfg.Upstreams, wantUp)
	}
	if cfg.TTL != 60 || cfg.ScanInterval != time.Minute {
		t.Errorf("TTL/interval = %d/%v", cfg.TTL, cfg.ScanInterval)
	}
	if !cfg.DisableSweep || cfg.AnswerSingleLabel {
		t.Errorf("bools: sweep=%v single=%v", cfg.DisableSweep, cfg.AnswerSingleLabel)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q", cfg.LogLevel)
	}
	if cfg.WebUsername != "admin" || cfg.WebPassword != "secret" {
		t.Errorf("auth = %q/%q", cfg.WebUsername, cfg.WebPassword)
	}
}

func TestLoadErrors(t *testing.T) {
	cases := map[string]string{
		"unknown key":     "no_such_key: 1\n",
		"bad ttl":         "ttl: many\n",
		"bad duration":    "scan_interval: fast\n",
		"short interval":  "scan_interval: 1s\n",
		"bad cidr":        "scan_cidr: 192.168.1.1\n",
		"bad domain":      "domain: -bad-\n",
		"bad listen":      "dns_listen: 53\n",
		"lonely password": "web_password: x\n",
		"bad line":        "just some text\n",
		"bad log level":   "log_level: loud\n",
	}
	for name, content := range cases {
		if _, _, err := Load(writeTemp(t, content)); err == nil {
			t.Errorf("%s: expected error for %q", name, content)
		}
	}
}

func TestEmptyValuesKeepDefaults(t *testing.T) {
	path := writeTemp(t, "domain:\nscan_cidr:\n")
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Domain != Default().Domain {
		t.Errorf("Domain = %q, want default", cfg.Domain)
	}
}
