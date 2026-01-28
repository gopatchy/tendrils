//go:build linux

package tendrils

import (
	"bufio"
	"net"
	"os/exec"
	"strings"
)

func (t *Tendrils) parseARPTable() []arpEntry {
	cmd := exec.Command("cat", "/proc/net/arp")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var entries []arpEntry
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}

		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		ip := net.ParseIP(fields[0])
		if ip == nil {
			continue
		}

		flags := fields[2]
		if flags == "0x0" {
			continue
		}

		macStr := fields[3]
		if macStr == "00:00:00:00:00:00" {
			continue
		}

		mac, err := net.ParseMAC(macStr)
		if err != nil {
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
