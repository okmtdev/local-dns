// Package store keeps the device registry (MAC -> latest IP) and the
// DNS mappings (hostname -> MAC or static IP), persisting both to a
// single JSON file.
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/okmtdev/local-dns/internal/names"
)

// ErrCorrupt marks a state file that could not be parsed. Callers may
// move the file aside and retry with a fresh store.
var ErrCorrupt = errors.New("state file is corrupted")

// Device is a host observed on the local network, keyed by MAC address.
type Device struct {
	MAC       string    `json:"mac"`
	IP        string    `json:"ip,omitempty"`
	Hostname  string    `json:"hostname,omitempty"` // discovered via mDNS/NetBIOS
	Vendor    string    `json:"vendor,omitempty"`   // from OUI database
	Label     string    `json:"label,omitempty"`    // user-assigned friendly name
	Self      bool      `json:"self,omitempty"`     // the machine running local-dns
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Mapping assigns a DNS host name (relative to the configured domain)
// to either a device MAC address or a static IP. Exactly one of MAC
// and IP is set.
type Mapping struct {
	Hostname  string    `json:"hostname"`
	MAC       string    `json:"mac,omitempty"`
	IP        string    `json:"ip,omitempty"`
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SeenDevice is one scan observation.
type SeenDevice struct {
	MAC  string
	IP   string
	Self bool
}

// DeviceView is a Device enriched with derived fields for the API.
type DeviceView struct {
	Device
	Online bool     `json:"online"`
	Names  []string `json:"names"` // mapping hostnames pointing at this MAC
}

// MappingView is a Mapping enriched with derived fields for the API.
type MappingView struct {
	Mapping
	CurrentIP  string `json:"current_ip"`
	DeviceName string `json:"device_name,omitempty"`
	Online     bool   `json:"online"`
}

type persisted struct {
	Devices  []*Device  `json:"devices"`
	Mappings []*Mapping `json:"mappings"`
}

// Store is safe for concurrent use.
type Store struct {
	mu           sync.Mutex
	path         string
	onlineWindow time.Duration
	devices      map[string]*Device
	mappings     map[string]*Mapping
	dirty        bool
}

// Open loads the state file at path (which may not exist yet).
// onlineWindow controls how recently a device must have been seen to
// count as online.
func Open(path string, onlineWindow time.Duration) (*Store, error) {
	s := &Store{
		path:         path,
		onlineWindow: onlineWindow,
		devices:      map[string]*Device{},
		mappings:     map[string]*Mapping{},
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	var p persisted
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrCorrupt, path, err)
	}
	for _, d := range p.Devices {
		mac, err := names.NormalizeMAC(d.MAC)
		if err != nil {
			continue
		}
		d.MAC = mac
		s.devices[mac] = d
	}
	for _, m := range p.Mappings {
		m.Hostname = names.Normalize(m.Hostname)
		if names.ValidateLabels(m.Hostname) != nil {
			continue
		}
		if m.MAC != "" {
			mac, err := names.NormalizeMAC(m.MAC)
			if err != nil {
				continue
			}
			m.MAC = mac
		}
		s.mappings[m.Hostname] = m
	}
	return s, nil
}

// Save writes the state atomically (tmp file + rename).
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

// SaveIfDirty persists only when something changed since the last save.
func (s *Store) SaveIfDirty() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	p := persisted{
		Devices:  make([]*Device, 0, len(s.devices)),
		Mappings: make([]*Mapping, 0, len(s.mappings)),
	}
	for _, d := range s.devices {
		p.Devices = append(p.Devices, d)
	}
	sort.Slice(p.Devices, func(i, j int) bool { return p.Devices[i].MAC < p.Devices[j].MAC })
	for _, m := range s.mappings {
		p.Mappings = append(p.Mappings, m)
	}
	sort.Slice(p.Mappings, func(i, j int) bool { return p.Mappings[i].Hostname < p.Mappings[j].Hostname })

	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	os.Chmod(tmpName, 0o600)
	if err := os.Rename(tmpName, s.path); err != nil {
		os.Remove(tmpName)
		return err
	}
	s.dirty = false
	return nil
}

// ApplyScan records one scan result. The returned bool reports a
// material change (new device, IP change, ...) that warrants an
// immediate save; plain LastSeen refreshes only mark the store dirty
// for the periodic flush.
func (s *Store) ApplyScan(seen []SeenDevice, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	material := false
	for _, sd := range seen {
		mac, err := names.NormalizeMAC(sd.MAC)
		if err != nil {
			continue
		}
		d, ok := s.devices[mac]
		if !ok {
			d = &Device{MAC: mac, FirstSeen: now}
			s.devices[mac] = d
			material = true
		}
		if sd.IP != "" && d.IP != sd.IP {
			d.IP = sd.IP
			material = true
		}
		if sd.Self && !d.Self {
			d.Self = true
			material = true
		}
		d.LastSeen = now
		s.dirty = true
	}
	if material {
		s.dirty = true
	}
	return material
}

// SetDiscoveredHostname stores a hostname learned from mDNS/NetBIOS.
func (s *Store) SetDiscoveredHostname(mac, hostname string) bool {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[mac]
	if !ok || d.Hostname == hostname {
		return false
	}
	d.Hostname = hostname
	s.dirty = true
	return true
}

// SetVendor stores the OUI vendor of a device.
func (s *Store) SetVendor(mac, vendor string) bool {
	if vendor == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[mac]
	if !ok || d.Vendor == vendor {
		return false
	}
	d.Vendor = vendor
	s.dirty = true
	return true
}

// SetLabel sets the user-facing label of a device and persists.
func (s *Store) SetLabel(mac, label string) error {
	label = strings.TrimSpace(label)
	if len(label) > 100 {
		return fmt.Errorf("ラベルが長すぎます (100文字以内)")
	}
	normMAC, err := names.NormalizeMAC(mac)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[normMAC]
	if !ok {
		return fmt.Errorf("デバイス %s は登録されていません", normMAC)
	}
	d.Label = label
	s.dirty = true
	return s.saveLocked()
}

// DeleteDevice removes a device from the registry and persists.
// Mappings referencing the MAC are kept (they resolve again once the
// device reappears).
func (s *Store) DeleteDevice(mac string) error {
	normMAC, err := names.NormalizeMAC(mac)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.devices[normMAC]; !ok {
		return fmt.Errorf("デバイス %s は登録されていません", normMAC)
	}
	delete(s.devices, normMAC)
	s.dirty = true
	return s.saveLocked()
}

// SetMapping creates or updates a mapping and persists. Exactly one of
// mac and ip must be non-empty.
func (s *Store) SetMapping(hostname, mac, ip, note string) (Mapping, error) {
	hostname = names.Normalize(hostname)
	if err := names.ValidateLabels(hostname); err != nil {
		return Mapping{}, err
	}
	if (mac == "") == (ip == "") {
		return Mapping{}, fmt.Errorf("MACアドレスか固定IPのどちらか一方を指定してください")
	}
	if mac != "" {
		var err error
		mac, err = names.NormalizeMAC(mac)
		if err != nil {
			return Mapping{}, err
		}
	}
	if ip != "" {
		parsed := net.ParseIP(strings.TrimSpace(ip))
		if parsed == nil {
			return Mapping{}, fmt.Errorf("IPアドレスの形式が不正です: %q", ip)
		}
		ip = parsed.String()
	}
	if len(note) > 200 {
		return Mapping{}, fmt.Errorf("メモが長すぎます (200文字以内)")
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.mappings[hostname]
	if !ok {
		m = &Mapping{Hostname: hostname, CreatedAt: now}
		s.mappings[hostname] = m
	}
	m.MAC = mac
	m.IP = ip
	m.Note = strings.TrimSpace(note)
	m.UpdatedAt = now
	s.dirty = true
	if err := s.saveLocked(); err != nil {
		return *m, err
	}
	return *m, nil
}

// DeleteMapping removes a mapping and persists. It reports whether the
// mapping existed.
func (s *Store) DeleteMapping(hostname string) (bool, error) {
	hostname = names.Normalize(hostname)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.mappings[hostname]; !ok {
		return false, nil
	}
	delete(s.mappings, hostname)
	s.dirty = true
	return true, s.saveLocked()
}

// Device returns a copy of one device.
func (s *Store) Device(mac string) (Device, bool) {
	normMAC, err := names.NormalizeMAC(mac)
	if err != nil {
		return Device{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[normMAC]
	if !ok {
		return Device{}, false
	}
	return *d, true
}

// Devices returns all devices sorted by IP address (devices without an
// IP last), enriched with online state and assigned names.
func (s *Store) Devices(now time.Time) []DeviceView {
	s.mu.Lock()
	defer s.mu.Unlock()
	namesByMAC := map[string][]string{}
	for _, m := range s.mappings {
		if m.MAC != "" {
			namesByMAC[m.MAC] = append(namesByMAC[m.MAC], m.Hostname)
		}
	}
	out := make([]DeviceView, 0, len(s.devices))
	for _, d := range s.devices {
		hostnames := namesByMAC[d.MAC]
		sort.Strings(hostnames)
		if hostnames == nil {
			hostnames = []string{}
		}
		out = append(out, DeviceView{
			Device: *d,
			Online: s.onlineLocked(d, now),
			Names:  hostnames,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := parseIPv4Key(out[i].IP), parseIPv4Key(out[j].IP)
		if c := bytes.Compare(a, b); c != 0 {
			return c < 0
		}
		return out[i].MAC < out[j].MAC
	})
	return out
}

// Counts returns (total, online) device counts.
func (s *Store) Counts(now time.Time) (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	online := 0
	for _, d := range s.devices {
		if s.onlineLocked(d, now) {
			online++
		}
	}
	return len(s.devices), online
}

// Mappings returns all mappings sorted by hostname, enriched with the
// currently resolved IP and device info.
func (s *Store) Mappings(now time.Time) []MappingView {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]MappingView, 0, len(s.mappings))
	for _, m := range s.mappings {
		v := MappingView{Mapping: *m}
		if m.IP != "" {
			v.CurrentIP = m.IP
			v.Online = true // static: always resolvable
		} else if d, ok := s.devices[m.MAC]; ok {
			v.CurrentIP = d.IP
			v.Online = s.onlineLocked(d, now)
			if d.Label != "" {
				v.DeviceName = d.Label
			} else if d.Hostname != "" {
				v.DeviceName = d.Hostname
			}
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out
}

// ResolveName resolves a mapping hostname (relative name, lowercase)
// to an IP. found reports whether the mapping exists; the IP may be
// nil when the mapped device has never been seen.
func (s *Store) ResolveName(hostname string) (net.IP, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.mappings[hostname]
	if !ok {
		return nil, false
	}
	return s.resolveLocked(m), true
}

// ResolvePTR finds a mapping whose current address equals ip and
// returns its hostname (relative to the domain).
func (s *Store) ResolvePTR(ip net.IP) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hostnames := make([]string, 0, len(s.mappings))
	for h := range s.mappings {
		hostnames = append(hostnames, h)
	}
	sort.Strings(hostnames)
	for _, h := range hostnames {
		if cur := s.resolveLocked(s.mappings[h]); cur != nil && cur.Equal(ip) {
			return h, true
		}
	}
	return "", false
}

func (s *Store) resolveLocked(m *Mapping) net.IP {
	if m.IP != "" {
		return net.ParseIP(m.IP)
	}
	if d, ok := s.devices[m.MAC]; ok && d.IP != "" {
		return net.ParseIP(d.IP)
	}
	return nil
}

func (s *Store) onlineLocked(d *Device, now time.Time) bool {
	return !d.LastSeen.IsZero() && now.Sub(d.LastSeen) <= s.onlineWindow
}

// parseIPv4Key returns a sortable key; unparsable/empty IPs sort last.
func parseIPv4Key(ip string) []byte {
	p := net.ParseIP(ip)
	if p == nil {
		return []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	}
	if v4 := p.To4(); v4 != nil {
		return append([]byte{0}, v4...)
	}
	return append([]byte{1}, p.To16()...)
}
