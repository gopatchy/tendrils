package tendrils

import (
	"bufio"
	"log"
	"net"
	"regexp"
	"time"
)

var yamahaModelRegex = regexp.MustCompile(`PA-Platform:ModelId\s*=\s*0x[0-9a-fA-F]+\(([^)]+)\)`)

func (t *Tendrils) probeYamahaDevice(ip net.IP) string {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), "50000"), 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if match := yamahaModelRegex.FindStringSubmatch(line); match != nil {
			model := match[1]
			if t.DebugYamaha {
				log.Printf("[yamaha] %s: found model %s", ip, model)
			}
			t.nodes.Update(nil, nil, []net.IP{ip}, "", model, "yamaha")
			return model
		}
	}

	return ""
}
