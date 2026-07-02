package scanner

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
)

// neighbor is one ARP table entry.
type neighbor struct {
	IP  string
	MAC string
	Dev string
}

const procNetARP = "/proc/net/arp"

// readARPTable reads the kernel ARP cache.
func readARPTable(path string) ([]neighbor, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseARPTable(f), nil
}

// parseARPTable parses /proc/net/arp content. Only complete Ethernet
// entries are returned; incomplete/failed entries (flags without
// ATF_COM) and the all-zero MAC are skipped.
func parseARPTable(r io.Reader) []neighbor {
	const (
		hwTypeEther = 0x1
		atfCom      = 0x2
	)
	var out []neighbor
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first { // header: "IP address  HW type  Flags  HW address  Mask  Device"
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		hwType, err := strconv.ParseUint(strings.TrimPrefix(fields[1], "0x"), 16, 32)
		if err != nil || hwType != hwTypeEther {
			continue
		}
		flags, err := strconv.ParseUint(strings.TrimPrefix(fields[2], "0x"), 16, 32)
		if err != nil || flags&atfCom == 0 {
			continue
		}
		mac := strings.ToLower(fields[3])
		if mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" {
			continue
		}
		out = append(out, neighbor{IP: fields[0], MAC: mac, Dev: fields[5]})
	}
	return out
}
