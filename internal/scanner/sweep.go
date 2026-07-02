package scanner

import (
	"context"
	"net"
	"sync"
	"time"
)

// sweep nudges every host in the subnet with a tiny UDP datagram
// (port 9, discard). The payload is irrelevant: sending forces the
// kernel to ARP-resolve each address, which refreshes /proc/net/arp
// for hosts that are actually present. No privileges are required.
func sweep(ctx context.Context, ips []net.IP, self net.IP) {
	sem := make(chan struct{}, 128)
	var wg sync.WaitGroup
	for _, ip := range ips {
		if self != nil && ip.Equal(self) {
			continue
		}
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(ip net.IP) {
			defer func() { <-sem; wg.Done() }()
			c, err := net.DialTimeout("udp4", net.JoinHostPort(ip.String(), "9"), 300*time.Millisecond)
			if err != nil {
				return
			}
			c.Write([]byte{0}) //nolint:errcheck // fire and forget
			c.Close()
		}(ip)
	}
	wg.Wait()
}
