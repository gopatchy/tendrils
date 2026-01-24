package tendrils

import (
	"context"
	"log"
	"net"
	"strings"
	"time"
)

func (t *Tendrils) pollARP(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.readARPTable()
		}
	}
}

type arpEntry struct {
	ip    net.IP
	mac   net.HardwareAddr
	iface string
}

func (t *Tendrils) readARPTable() {
	entries := t.parseARPTable()
	localNode := t.getLocalNode()

	for _, entry := range entries {
		if t.Interface != "" && entry.iface != t.Interface {
			continue
		}
		if isBroadcastOrZero(entry.mac) {
			continue
		}

		if t.DebugARP {
			log.Printf("[arp] %s: ip=%s mac=%s", entry.iface, entry.ip, entry.mac)
		}

		t.nodes.Update(nil, entry.mac, []net.IP{entry.ip}, "", "", "arp")
		if localNode != nil {
			t.nodes.UpdateMACTable(localNode, entry.mac, entry.iface)
		}
	}
}

func normalizeMACAddress(mac string) string {
	parts := strings.Split(mac, ":")
	for i, part := range parts {
		if len(part) == 1 {
			parts[i] = "0" + part
		}
	}
	return strings.Join(parts, ":")
}

func (t *Tendrils) requestARP(ip net.IP) {
	if t.DisableARP {
		return
	}
	conn, err := net.DialTimeout("udp4", ip.String()+":1", 100*time.Millisecond)
	if err == nil {
		conn.Close()
	}
}
