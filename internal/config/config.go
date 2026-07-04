// Package config loads the local-dns configuration file.
//
// The file format is a flat "key: value" text file (a strict subset of
// YAML): one setting per line, "#" starts a comment line, blank lines
// are ignored. Lists are written as comma-separated values.
package config

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/okmtdev/local-dns/internal/names"
)

// Config holds all runtime settings.
type Config struct {
	// Domain is the DNS zone this server is authoritative for
	// (e.g. "home.arpa"). Managed names live under this domain.
	Domain string
	// DNSListen is the listen address for the DNS server (UDP+TCP).
	DNSListen string
	// WebListen is the listen address for the Web UI / API.
	WebListen string
	// Upstreams are resolvers that receive every query outside Domain.
	Upstreams []string
	// TTL is the TTL (seconds) for records served from mappings.
	TTL uint32
	// ScanInterval is how often the network is scanned.
	ScanInterval time.Duration
	// ScanCIDR optionally overrides the auto-detected target subnet.
	ScanCIDR string
	// ScanInterface optionally pins scanning to one interface.
	ScanInterface string
	// DisableSweep turns off the active sweep (passive ARP only).
	DisableSweep bool
	// StatePath is where devices/mappings are persisted as JSON.
	StatePath string
	// OUIPaths are extra OUI database files for vendor lookup.
	OUIPaths []string
	// WebUsername/WebPassword enable HTTP Basic auth when both set.
	WebUsername string
	WebPassword string
	// AnswerSingleLabel makes bare single-label queries ("nas") answered
	// from mappings as well, not only "nas.<domain>".
	AnswerSingleLabel bool
	// LogLevel is one of debug, info, warn, error.
	LogLevel string
}

// Default returns the built-in defaults.
func Default() Config {
	return Config{
		Domain:            "home.arpa",
		DNSListen:         ":53",
		WebListen:         ":80",
		Upstreams:         []string{"1.1.1.1:53", "8.8.8.8:53"},
		TTL:               30,
		ScanInterval:      30 * time.Second,
		StatePath:         "/var/lib/local-dns/state.json",
		AnswerSingleLabel: true,
		LogLevel:          "info",
	}
}

// Load reads the configuration file at path. A missing file is not an
// error: defaults are returned and found=false.
func Load(path string) (cfg Config, found bool, err error) {
	cfg = Default()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, false, nil
		}
		return cfg, false, err
	}
	defer f.Close()
	if err := parse(&cfg, f); err != nil {
		return cfg, true, fmt.Errorf("%s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return cfg, true, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, true, nil
}

func parse(cfg *Config, f *os.File) error {
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return fmt.Errorf("line %d: expected \"key: value\", got %q", lineNo, line)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if err := apply(cfg, key, value); err != nil {
			return fmt.Errorf("line %d: %w", lineNo, err)
		}
	}
	return sc.Err()
}

func apply(cfg *Config, key, value string) error {
	if value == "" {
		return nil // keep default
	}
	var err error
	switch key {
	case "domain":
		cfg.Domain = value
	case "dns_listen":
		cfg.DNSListen = value
	case "web_listen":
		cfg.WebListen = value
	case "upstreams":
		cfg.Upstreams = splitList(value)
	case "ttl":
		v, e := strconv.ParseUint(value, 10, 32)
		if e != nil {
			return fmt.Errorf("ttl: %q is not a number", value)
		}
		cfg.TTL = uint32(v)
	case "scan_interval":
		cfg.ScanInterval, err = time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("scan_interval: %q is not a duration (e.g. 30s, 1m)", value)
		}
	case "scan_cidr":
		cfg.ScanCIDR = value
	case "scan_interface":
		cfg.ScanInterface = value
	case "disable_sweep":
		cfg.DisableSweep, err = parseBool(value)
		if err != nil {
			return fmt.Errorf("disable_sweep: %w", err)
		}
	case "state_path":
		cfg.StatePath = value
	case "oui_paths":
		cfg.OUIPaths = splitList(value)
	case "web_username":
		cfg.WebUsername = value
	case "web_password":
		cfg.WebPassword = value
	case "answer_single_label":
		cfg.AnswerSingleLabel, err = parseBool(value)
		if err != nil {
			return fmt.Errorf("answer_single_label: %w", err)
		}
	case "log_level":
		cfg.LogLevel = strings.ToLower(value)
	default:
		return fmt.Errorf("unknown key %q", key)
	}
	return nil
}

func (c *Config) validate() error {
	c.Domain = names.Normalize(c.Domain)
	if err := names.ValidateLabels(c.Domain); err != nil {
		return fmt.Errorf("domain: %w", err)
	}
	for _, addr := range []struct{ key, v string }{
		{"dns_listen", c.DNSListen},
		{"web_listen", c.WebListen},
	} {
		if _, _, err := net.SplitHostPort(addr.v); err != nil {
			return fmt.Errorf("%s: %q is not a listen address (e.g. \":53\", \"192.168.1.2:53\")", addr.key, addr.v)
		}
	}
	if len(c.Upstreams) == 0 {
		return fmt.Errorf("upstreams: at least one upstream resolver is required")
	}
	for i, up := range c.Upstreams {
		normalized, err := normalizeHostPort(up, "53")
		if err != nil {
			return fmt.Errorf("upstreams: %w", err)
		}
		c.Upstreams[i] = normalized
	}
	if c.TTL < 1 || c.TTL > 86400 {
		return fmt.Errorf("ttl: must be between 1 and 86400")
	}
	if c.ScanInterval < 5*time.Second || c.ScanInterval > time.Hour {
		return fmt.Errorf("scan_interval: must be between 5s and 1h")
	}
	if c.ScanCIDR != "" {
		if _, _, err := net.ParseCIDR(c.ScanCIDR); err != nil {
			return fmt.Errorf("scan_cidr: %q is not a CIDR (e.g. 192.168.1.0/24)", c.ScanCIDR)
		}
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level: must be one of debug, info, warn, error")
	}
	if (c.WebUsername == "") != (c.WebPassword == "") {
		return fmt.Errorf("web_username and web_password must be set together")
	}
	return nil
}

// normalizeHostPort appends the default port when missing and handles
// bare IPv6 addresses ("2001:db8::1" -> "[2001:db8::1]:53").
func normalizeHostPort(s, defaultPort string) (string, error) {
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s, nil
	}
	host := s
	if strings.Count(s, ":") >= 2 && !strings.Contains(s, "[") {
		host = "[" + s + "]"
	}
	joined := host + ":" + defaultPort
	if _, _, err := net.SplitHostPort(joined); err != nil {
		return "", fmt.Errorf("%q is not a valid address", s)
	}
	return joined, nil
}

func splitList(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseBool(v string) (bool, error) {
	switch strings.ToLower(v) {
	case "true", "yes", "on", "1":
		return true, nil
	case "false", "no", "off", "0":
		return false, nil
	}
	return false, fmt.Errorf("%q is not a boolean (true/false)", v)
}
