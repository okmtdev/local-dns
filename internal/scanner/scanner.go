// Package scanner discovers devices on the local network. Every scan
// sweeps the subnet with harmless UDP datagrams so the kernel refreshes
// its ARP cache, then reads /proc/net/arp to learn MAC/IP pairs, and
// finally probes new devices for their hostnames (mDNS, NetBIOS) and
// vendor (OUI database).
package scanner

import (
	"context"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/okmtdev/local-dns/internal/store"
)

const (
	maxSweepHosts    = 4096
	sweepSettle      = 1500 * time.Millisecond
	probeTimeout     = 1200 * time.Millisecond
	probeConcurrency = 8
	maxProbesPerScan = 16
	reprobeAfter     = 10 * time.Minute
)

// Scanner runs periodic network scans and feeds the store.
type Scanner struct {
	store        *store.Store
	oui          *OUITable
	log          *slog.Logger
	interval     time.Duration
	cidr         string
	iface        string
	disableSweep bool

	trigger chan struct{}

	mu        sync.Mutex
	lastScan  time.Time
	probedAt  map[string]time.Time // MAC -> last hostname probe
	probedIP  map[string]string    // MAC -> IP at last probe
	arpPath   string
	routePath string
}

// New creates a Scanner.
func New(st *store.Store, oui *OUITable, log *slog.Logger, interval time.Duration, cidr, iface string, disableSweep bool) *Scanner {
	return &Scanner{
		store:        st,
		oui:          oui,
		log:          log,
		interval:     interval,
		cidr:         cidr,
		iface:        iface,
		disableSweep: disableSweep,
		trigger:      make(chan struct{}, 1),
		probedAt:     map[string]time.Time{},
		probedIP:     map[string]string{},
		arpPath:      procNetARP,
	}
}

// Run scans immediately and then on every interval tick (or manual
// trigger) until ctx is cancelled.
func (s *Scanner) Run(ctx context.Context) {
	s.scan(ctx)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.scan(ctx)
		case <-s.trigger:
			s.scan(ctx)
		}
	}
}

// Trigger requests an immediate scan (used by the Web UI).
func (s *Scanner) Trigger() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

// LastScan returns the completion time of the most recent scan.
func (s *Scanner) LastScan() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastScan
}

func (s *Scanner) scan(ctx context.Context) {
	start := time.Now()
	nc, err := resolveNetwork(s.cidr, s.iface)
	if err != nil {
		s.log.Warn("network detection failed; reading ARP table unfiltered", "error", err)
	}

	if nc != nil && !s.disableSweep {
		ips := hostsInSubnet(nc.ipnet, maxSweepHosts)
		if ips == nil {
			s.log.Debug("subnet too large for active sweep; relying on passive ARP", "subnet", nc.ipnet.String())
		} else {
			sweep(ctx, ips, nc.selfIP)
			sleepCtx(ctx, sweepSettle)
		}
	}
	if ctx.Err() != nil {
		return
	}

	neighbors, err := readARPTable(s.arpPath)
	if err != nil {
		s.log.Error("reading ARP table failed", "error", err)
		return
	}

	now := time.Now()
	var seen []store.SeenDevice
	for _, n := range neighbors {
		if nc != nil {
			if nc.ifaceName != "" && n.Dev != nc.ifaceName {
				continue
			}
			if ip := parseV4(n.IP); ip == nil || !nc.ipnet.Contains(ip) {
				continue
			}
		}
		seen = append(seen, store.SeenDevice{MAC: n.MAC, IP: n.IP})
	}
	if nc != nil && nc.selfMAC != "" && nc.selfIP != nil {
		seen = append(seen, store.SeenDevice{MAC: nc.selfMAC, IP: nc.selfIP.String(), Self: true})
	}

	material := s.store.ApplyScan(seen, now)

	if nc != nil && nc.selfMAC != "" {
		if hn, err := os.Hostname(); err == nil {
			if short, _, _ := strings.Cut(hn, "."); short != "" {
				if s.store.SetDiscoveredHostname(nc.selfMAC, short) {
					material = true
				}
			}
		}
	}

	if s.probeHostnames(ctx, seen) {
		material = true
	}
	if s.fillVendors(seen) {
		material = true
	}

	if material {
		if err := s.store.Save(); err != nil {
			s.log.Error("saving state failed", "error", err)
		}
	}

	s.mu.Lock()
	s.lastScan = time.Now()
	s.mu.Unlock()
	s.log.Debug("scan finished", "devices", len(seen), "took", time.Since(start).Round(time.Millisecond))
}

// probeHostnames resolves hostnames for devices that are new, changed
// IP, or are still nameless (rate-limited per scan).
func (s *Scanner) probeHostnames(ctx context.Context, seen []store.SeenDevice) bool {
	type job struct{ mac, ip string }
	var jobs []job
	s.mu.Lock()
	for _, sd := range seen {
		if sd.Self || sd.IP == "" {
			continue
		}
		d, ok := s.store.Device(sd.MAC)
		if !ok {
			continue
		}
		mac := d.MAC
		last, probed := s.probedAt[mac]
		ipChanged := s.probedIP[mac] != sd.IP
		needsName := d.Hostname == ""
		if (!probed && needsName) || (probed && needsName && time.Since(last) > reprobeAfter) || (probed && ipChanged) {
			jobs = append(jobs, job{mac: mac, ip: sd.IP})
			s.probedAt[mac] = time.Now()
			s.probedIP[mac] = sd.IP
		}
		if len(jobs) >= maxProbesPerScan {
			break
		}
	}
	s.mu.Unlock()
	if len(jobs) == 0 || ctx.Err() != nil {
		return false
	}

	changed := false
	var mu sync.Mutex
	sem := make(chan struct{}, probeConcurrency)
	var wg sync.WaitGroup
	for _, j := range jobs {
		sem <- struct{}{}
		wg.Add(1)
		go func(j job) {
			defer func() { <-sem; wg.Done() }()
			ip := parseV4(j.ip)
			if ip == nil {
				return
			}
			if host := probeHostname(ip, probeTimeout); host != "" {
				if s.store.SetDiscoveredHostname(j.mac, host) {
					mu.Lock()
					changed = true
					mu.Unlock()
				}
			}
		}(j)
	}
	wg.Wait()
	return changed
}

func (s *Scanner) fillVendors(seen []store.SeenDevice) bool {
	if s.oui == nil {
		return false
	}
	changed := false
	for _, sd := range seen {
		d, ok := s.store.Device(sd.MAC)
		if !ok || d.Vendor != "" {
			continue
		}
		if v := s.oui.Lookup(d.MAC); v != "" {
			if s.store.SetVendor(d.MAC, v) {
				changed = true
			}
		}
	}
	return changed
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func parseV4(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	return ip.To4()
}
