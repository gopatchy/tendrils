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

func isSkaarhojService(s string) bool {
	return strings.Contains(s, "_skaarhoj._tcp")
}

func extractSkaarhojName(s string) string {
	idx := strings.Index(s, "._skaarhoj._tcp")
	if idx <= 0 {
		return ""
	}
	return strings.ReplaceAll(s[:idx], "\\", "")
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

	go t.runMDNSQuerier(ctx, iface, conn)

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
	allRecords := append(msg.Answer, msg.Extra...)

	if t.DebugMDNS {
		for _, rr := range allRecords {
			log.Printf("[mdns] %s: record %s", ifaceName, rr.String())
		}
	}

	aRecords := map[string]net.IP{}
	srvTargets := map[string]string{}
	danteNames := map[string]bool{}
	danteARCPorts := map[string]uint16{}
	skaarhojNames := map[string]bool{}

	for _, rr := range allRecords {
		switch r := rr.(type) {
		case *dns.A:
			name := strings.TrimSuffix(r.Hdr.Name, ".")
			aRecords[name] = r.A
		case *dns.AAAA:
			continue
		case *dns.PTR:
			if isDanteService(r.Hdr.Name) {
				name := extractDanteName(r.Ptr)
				if name != "" {
					danteNames[name] = true
				}
			}
			if isSkaarhojService(r.Ptr) {
				name := extractSkaarhojName(r.Ptr)
				if name != "" {
					skaarhojNames[name] = true
				}
			}
		case *dns.SRV:
			target := strings.TrimSuffix(r.Target, ".")
			if isDanteService(r.Hdr.Name) {
				name := extractDanteName(r.Hdr.Name)
				if name != "" {
					danteNames[name] = true
					if target != "" {
						srvTargets[name] = target
					}
					if strings.Contains(r.Hdr.Name, "_netaudio-arc.") && r.Port > 0 {
						danteARCPorts[name] = r.Port
					}
				}
			}
			if isSkaarhojService(r.Hdr.Name) {
				name := extractSkaarhojName(r.Hdr.Name)
				if name != "" {
					skaarhojNames[name] = true
					if target != "" {
						srvTargets[name] = target
					}
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
		arcPort := int(danteARCPorts[name])
		t.nodes.UpdateDante(name, ip, arcPort)
	}

	for name := range skaarhojNames {
		var ip net.IP
		if target, ok := srvTargets[name]; ok {
			ip = aRecords[target]
		}
		if ip == nil {
			ip = srcIP
		}
		if t.DebugMDNS {
			log.Printf("[mdns] %s: skaarhoj %s -> %s", ifaceName, name, ip)
		}
		t.nodes.Update(nil, nil, []net.IP{ip}, "", name, "skaarhoj")
	}

	if len(danteNames) == 0 && len(skaarhojNames) == 0 {
		for aName, ip := range aRecords {
			hostname := strings.TrimSuffix(aName, ".local")
			if hostname != "" && hostname != aName {
				if t.DebugMDNS {
					log.Printf("[mdns] %s: %s -> %s", ifaceName, ip, hostname)
				}
				t.nodes.Update(nil, nil, []net.IP{ip}, "", hostname, "mdns")
			}
		}
	}
}

var mdnsServices = []string{
	"_services._dns-sd._udp.local.",
	"_netaudio-arc._udp.local.",
	"_netaudio-cmc._udp.local.",
	"_netaudio-dbc._udp.local.",
	"_netaudio-chan._udp.local.",
	"_dantevideo._udp.local.",
	"_danteancil._udp.local.",
}

func (t *Tendrils) runMDNSQuerier(ctx context.Context, iface net.Interface, conn *net.UDPConn) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	t.sendMDNSQueries(iface.Name, conn)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.sendMDNSQueries(iface.Name, conn)
		}
	}
}

func (t *Tendrils) sendMDNSQueries(ifaceName string, conn *net.UDPConn) {
	dest := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

	for _, service := range mdnsServices {
		msg := new(dns.Msg)
		msg.SetQuestion(service, dns.TypePTR)
		msg.RecursionDesired = false

		data, err := msg.Pack()
		if err != nil {
			continue
		}

		conn.WriteToUDP(data, dest)
	}

	if t.DebugMDNS {
		log.Printf("[mdns] %s: sent queries for %d services", ifaceName, len(mdnsServices))
	}
}
