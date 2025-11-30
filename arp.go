package tendrils

import (
	"bufio"
	"context"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func (t *Tendrils) pollARP(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	t.readARPTable()

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

	for _, entry := range entries {
		if isBroadcastOrZero(entry.mac) {
			continue
		}

		t.nodes.Update([]net.IP{entry.ip}, []net.HardwareAddr{entry.mac}, entry.iface, "", "arp")
	}
}

func (t *Tendrils) parseARPTable() []arpEntry {
	if runtime.GOOS == "darwin" {
		return t.parseARPDarwin()
	}
	return t.parseARPLinux()
}

func (t *Tendrils) parseARPDarwin() []arpEntry {
	cmd := exec.Command("arp", "-a")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var entries []arpEntry
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "permanent") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		ipStr := strings.Trim(fields[1], "()")
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		macStr := fields[3]
		if macStr == "(incomplete)" {
			continue
		}

		macStr = normalizeMACAddress(macStr)
		mac, err := net.ParseMAC(macStr)
		if err != nil {
			log.Printf("[arp] failed to parse MAC %q for IP %s: %v", macStr, ipStr, err)
			continue
		}

		ifaceName := fields[5]

		entries = append(entries, arpEntry{
			ip:    ip,
			mac:   mac,
			iface: ifaceName,
		})
	}

	return entries
}

func (t *Tendrils) parseARPLinux() []arpEntry {
	var entries []arpEntry
	return entries
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
