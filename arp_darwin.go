//go:build darwin

package tendrils

import (
	"bufio"
	"log"
	"net"
	"os/exec"
	"strings"
)

func (t *Tendrils) parseARPTable() []arpEntry {
	cmd := exec.Command("arp", "-an")
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
