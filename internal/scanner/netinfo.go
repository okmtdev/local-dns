package scanner

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// netContext describes the subnet a scan targets.
type netContext struct {
	ifaceName string
	ipnet     *net.IPNet // target subnet
	selfIP    net.IP     // our IPv4 on that subnet (may be nil)
	selfMAC   string     // may be ""
}

// resolveNetwork determines the target subnet from an explicit CIDR,
// an explicit interface name, or auto-detection (default route).
func resolveNetwork(cidr, ifaceName string) (*netContext, error) {
	if cidr != "" {
		_, ipn, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid scan_cidr %q: %w", cidr, err)
		}
		nc := &netContext{ipnet: ipn, ifaceName: ifaceName}
		nc.fillSelf()
		return nc, nil
	}
	name := ifaceName
	if name == "" {
		var err error
		name, err = defaultRouteIface("/proc/net/route")
		if err != nil {
			name, err = firstPrivateIface()
			if err != nil {
				return nil, fmt.Errorf("could not auto-detect a network interface: %w (set scan_interface or scan_cidr)", err)
			}
		}
	}
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", name, err)
	}
	ip, ipn, err := firstIPv4(ifi)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", name, err)
	}
	return &netContext{
		ifaceName: name,
		ipnet:     &net.IPNet{IP: ip.Mask(ipn.Mask), Mask: ipn.Mask},
		selfIP:    ip,
		selfMAC:   ifi.HardwareAddr.String(),
	}, nil
}

// fillSelf finds our own address inside the target subnet, trying the
// pinned interface first and then all interfaces.
func (nc *netContext) fillSelf() {
	try := func(ifi net.Interface) bool {
		addrs, err := ifi.Addrs()
		if err != nil {
			return false
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			v4 := ipn.IP.To4()
			if v4 == nil || !nc.ipnet.Contains(v4) {
				continue
			}
			nc.ifaceName = ifi.Name
			nc.selfIP = v4
			nc.selfMAC = ifi.HardwareAddr.String()
			return true
		}
		return false
	}
	if nc.ifaceName != "" {
		if ifi, err := net.InterfaceByName(nc.ifaceName); err == nil && try(*ifi) {
			return
		}
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagUp == 0 {
			continue
		}
		if try(ifi) {
			return
		}
	}
}

func firstIPv4(ifi *net.Interface) (net.IP, *net.IPNet, error) {
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, nil, err
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		v4 := ipn.IP.To4()
		if v4 == nil || v4.IsLinkLocalUnicast() || v4.IsLoopback() {
			continue
		}
		return v4, ipn, nil
	}
	return nil, nil, fmt.Errorf("no usable IPv4 address")
}

// defaultRouteIface parses /proc/net/route and returns the interface
// that carries the default route.
func defaultRouteIface(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first { // header line
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		// Iface Destination Gateway Flags ...
		if len(fields) < 4 {
			continue
		}
		const rtfUp = 0x1
		if fields[1] == "00000000" && flagsSet(fields[3], rtfUp) {
			return fields[0], nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("no default route in %s", path)
}

func flagsSet(hexFlags string, mask uint64) bool {
	var v uint64
	for _, c := range strings.ToLower(hexFlags) {
		switch {
		case c >= '0' && c <= '9':
			v = v<<4 | uint64(c-'0')
		case c >= 'a' && c <= 'f':
			v = v<<4 | uint64(c-'a'+10)
		default:
			return false
		}
	}
	return v&mask != 0
}

// firstPrivateIface returns the first up, non-loopback interface with
// a private IPv4 address.
func firstPrivateIface() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if v4 := ipn.IP.To4(); v4 != nil && v4.IsPrivate() {
					return ifi.Name, nil
				}
			}
		}
	}
	return "", fmt.Errorf("no interface with a private IPv4 address")
}

// hostsInSubnet enumerates all host addresses of a subnet, skipping
// the network and broadcast addresses. It returns nil when the subnet
// holds more than maxHosts addresses.
func hostsInSubnet(ipn *net.IPNet, maxHosts int) []net.IP {
	ones, bits := ipn.Mask.Size()
	if bits != 32 {
		return nil // IPv4 only
	}
	total := 1 << (32 - ones)
	if total-2 > maxHosts {
		return nil
	}
	base := ipn.IP.Mask(ipn.Mask).To4()
	if base == nil {
		return nil
	}
	base32 := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	var out []net.IP
	for i := 0; i < total; i++ {
		if ones < 31 && (i == 0 || i == total-1) {
			continue // network / broadcast
		}
		v := base32 + uint32(i)
		out = append(out, net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).To4())
	}
	return out
}
