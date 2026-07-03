package scanner

import (
	"bufio"
	"os"
	"strings"
)

// OUITable maps the first three MAC octets ("AABBCC") to vendor names.
// A nil table is valid and always misses.
type OUITable struct {
	m map[string]string
}

// DefaultOUIPaths are probed in order; install the Ubuntu "ieee-data"
// package (or nmap / wireshark) to get vendor names.
var DefaultOUIPaths = []string{
	"/usr/share/ieee-data/oui.txt",
	"/var/lib/ieee-data/oui.txt",
	"/usr/share/misc/oui.txt",
	"/usr/share/nmap/nmap-mac-prefixes",
	"/usr/share/wireshark/manuf",
}

// LoadOUI reads every readable file in paths and merges the entries.
// Returns nil when no file yielded any entry.
func LoadOUI(paths []string) *OUITable {
	m := map[string]string{}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		parseOUI(f, m)
		f.Close()
	}
	if len(m) == 0 {
		return nil
	}
	return &OUITable{m: m}
}

// Len returns the number of known prefixes.
func (t *OUITable) Len() int {
	if t == nil {
		return 0
	}
	return len(t.m)
}

// Lookup returns the vendor for a normalized MAC ("aa:bb:cc:dd:ee:ff").
func (t *OUITable) Lookup(mac string) string {
	if t == nil {
		return ""
	}
	key := ouiKey(mac)
	if key == "" {
		return ""
	}
	return t.m[key]
}

func ouiKey(mac string) string {
	var b strings.Builder
	for _, c := range mac {
		switch {
		case c >= '0' && c <= '9':
			b.WriteRune(c)
		case c >= 'a' && c <= 'f':
			b.WriteRune(c - 32)
		case c >= 'A' && c <= 'F':
			b.WriteRune(c)
		case c == ':' || c == '-' || c == '.':
		default:
			return ""
		}
		if b.Len() == 6 {
			return b.String()
		}
	}
	return ""
}

// parseOUI understands the three common database formats:
//
//	IEEE oui.txt:     "28-6F-B9   (hex)\t\tNokia Shanghai Bell"
//	nmap:             "286FB9 Nokia Shanghai Bell"
//	wireshark manuf:  "28:6F:B9\tNokia\tNokia Shanghai Bell"
func parseOUI(f *os.File, into map[string]string) {
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 256*1024)
	sc.Buffer(buf, 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		token, rest, _ := strings.Cut(line, "\t")
		if i := strings.IndexByte(token, ' '); i >= 0 {
			rest = token[i+1:] + "\t" + rest
			token = token[:i]
		}
		if strings.Contains(token, "/") {
			continue // wireshark block entries like 00:50:C2:00:00:00/36
		}
		key := ouiKey(token)
		if key == "" || len(strings.ReplaceAll(strings.ReplaceAll(token, ":", ""), "-", "")) != 6 {
			continue
		}
		name := strings.TrimSpace(rest)
		name = strings.TrimPrefix(name, "(hex)")
		name = strings.TrimPrefix(name, "(base 16)")
		name = strings.TrimSpace(name)
		// wireshark manuf: prefer the long name in the last column.
		if cols := strings.Split(name, "\t"); len(cols) > 1 {
			last := strings.TrimSpace(cols[len(cols)-1])
			if last != "" {
				name = last
			} else {
				name = strings.TrimSpace(cols[0])
			}
		}
		if name == "" {
			continue
		}
		if _, exists := into[key]; !exists {
			into[key] = name
		}
	}
}
