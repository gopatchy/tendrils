package tendrils

import (
	"context"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	mdnsAddr = "224.0.0.251:5353"
)

func extractDanteName(s string) string {
	var name string
	for _, prefix := range []string{"._netaudio-", "._dante"} {
		if idx := strings.Index(s, prefix); idx > 0 {
			name = s[:idx]
			break
		}
	}
	if name == "" {
		return ""
	}
	if at := strings.LastIndex(name, "@"); at >= 0 {
		name = name[at+1:]
	}
	return name
}

func isDanteService(s string) bool {
	return strings.Contains(s, "_netaudio-") || strings.Contains(s, "._dante")
}

func (t *Tendrils) listenMDNS(ctx context.Context, iface net.Interface) {
	addr, err := net.ResolveUDPAddr("udp4", mdnsAddr)
	if err != nil {
		log.Printf("[ERROR] failed to resolve mdns address: %v", err)
		return
	}

	conn, err := net.ListenMulticastUDP("udp4", &iface, addr)
	if err != nil {
		log.Printf("[ERROR] failed to listen mdns on %s: %v", iface.Name, err)
		return
	}
	defer conn.Close()

	go t.runMDNSQuerier(ctx, iface)

	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			continue
		}

		t.handleMDNSPacket(iface.Name, src.IP, buf[:n])
	}
}

func (t *Tendrils) handleMDNSPacket(ifaceName string, srcIP net.IP, data []byte) {
	msg := new(dns.Msg)
	if err := msg.Unpack(data); err != nil {
		return
	}

	if msg.Response {
		t.processMDNSResponse(ifaceName, srcIP, msg)
	}
}

func (t *Tendrils) processMDNSResponse(ifaceName string, srcIP net.IP, msg *dns.Msg) {
	var hostname string

	allRecords := append(msg.Answer, msg.Extra...)

	if t.DebugMDNS {
		for _, rr := range allRecords {
			log.Printf("[mdns] %s: record %s", ifaceName, rr.String())
		}
	}

	aRecords := map[string]net.IP{}
	srvTargets := map[string]string{}
	danteNames := map[string]bool{}

	for _, rr := range allRecords {
		switch r := rr.(type) {
		case *dns.A:
			name := strings.TrimSuffix(r.Hdr.Name, ".")
			aRecords[name] = r.A
			localName := strings.TrimSuffix(name, ".local")
			if localName != "" && r.A.Equal(srcIP) {
				hostname = localName
			}
		case *dns.AAAA:
			continue
		case *dns.PTR:
			if isDanteService(r.Hdr.Name) {
				name := extractDanteName(r.Ptr)
				if name != "" {
					danteNames[name] = true
				}
			} else {
				name := strings.TrimSuffix(r.Ptr, ".local.")
				name = strings.TrimSuffix(name, ".")
				if hostname == "" && name != "" && !strings.HasPrefix(name, "_") {
					hostname = name
				}
			}
		case *dns.SRV:
			if isDanteService(r.Hdr.Name) {
				name := extractDanteName(r.Hdr.Name)
				target := strings.TrimSuffix(r.Target, ".")
				if name != "" && target != "" {
					srvTargets[name] = target
				}
			}
		}
	}

	for name := range danteNames {
		var ip net.IP
		if target, ok := srvTargets[name]; ok {
			ip = aRecords[target]
		}
		if ip == nil {
			ip = aRecords[name+".local"]
		}
		if ip == nil {
			ip = srcIP
		}
		t.nodes.UpdateDante(name, ip)
	}

	if len(danteNames) == 0 && hostname != "" {
		if t.DebugMDNS {
			log.Printf("[mdns] %s: %s -> %s", ifaceName, srcIP, hostname)
		}
		t.nodes.Update(nil, nil, []net.IP{srcIP}, "", hostname, "mdns")
	}
}

func (t *Tendrils) runMDNSQuerier(ctx context.Context, iface net.Interface) {
	addrs, err := iface.Addrs()
	if err != nil {
		return
	}

	var srcIP net.IP
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			srcIP = ipnet.IP.To4()
			break
		}
	}
	if srcIP == nil {
		return
	}

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	t.sendMDNSQuery(iface.Name, srcIP)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.sendMDNSQuery(iface.Name, srcIP)
		}
	}
}

func (t *Tendrils) sendMDNSQuery(ifaceName string, srcIP net.IP) {
	conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: srcIP}, &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353})
	if err != nil {
		return
	}
	defer conn.Close()

	msg := new(dns.Msg)
	msg.SetQuestion("_services._dns-sd._udp.local.", dns.TypePTR)
	msg.RecursionDesired = false

	data, err := msg.Pack()
	if err != nil {
		return
	}

	conn.Write(data)

	if t.DebugMDNS {
		log.Printf("[mdns] %s: sent query", ifaceName)
	}
}
