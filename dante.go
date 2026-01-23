package tendrils

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/miekg/dns"
)

func (t *Tendrils) listenDante(ctx context.Context, iface net.Interface) {
	go t.queryDanteMDNS(ctx, iface)
	go t.listenPTP(ctx, iface)
}

func (t *Tendrils) queryDanteMDNS(ctx context.Context, iface net.Interface) {
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

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	t.sendDanteMDNSQuery(iface.Name, srcIP)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.sendDanteMDNSQuery(iface.Name, srcIP)
		}
	}
}

func (t *Tendrils) sendDanteMDNSQuery(ifaceName string, srcIP net.IP) {
	conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: srcIP}, &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353})
	if err != nil {
		return
	}
	defer conn.Close()

	services := []string{
		"_netaudio-arc._udp.local.",
		"_netaudio-cmc._udp.local.",
		"_netaudio-dbc._udp.local.",
		"_netaudio-chan._udp.local.",
		"_dantevideo._udp.local.",
		"_dantevid-flow._udp.local.",
	}

	for _, service := range services {
		msg := new(dns.Msg)
		msg.SetQuestion(service, dns.TypePTR)
		msg.RecursionDesired = false

		data, err := msg.Pack()
		if err != nil {
			continue
		}

		conn.Write(data)
	}

	if t.DebugDante {
		log.Printf("[dante] %s: sent mdns queries for netaudio services", ifaceName)
	}
}

func (t *Tendrils) listenPTP(ctx context.Context, iface net.Interface) {
	addr, err := net.ResolveUDPAddr("udp4", "224.0.1.129:319")
	if err != nil {
		return
	}

	conn, err := net.ListenMulticastUDP("udp4", &iface, addr)
	if err != nil {
		if t.DebugDante {
			log.Printf("[dante] %s: failed to listen ptp: %v", iface.Name, err)
		}
		return
	}
	defer conn.Close()

	buf := make([]byte, 1500)
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

		t.handlePTPPacket(iface.Name, src.IP, buf[:n])
	}
}

func (t *Tendrils) handlePTPPacket(ifaceName string, srcIP net.IP, data []byte) {
	if len(data) < 34 {
		return
	}

	messageType := data[0] & 0x0f

	if messageType != 0x0b {
		return
	}

	if len(data) < 64 {
		return
	}

	clockClass := data[48]
	clockAccuracy := data[49]
	priority1 := data[47]
	priority2 := data[51]

	if t.DebugDante {
		log.Printf("[dante] %s: ptp announce from %s class=%d accuracy=%d p1=%d p2=%d",
			ifaceName, srcIP, clockClass, clockAccuracy, priority1, priority2)
	}

	t.nodes.SetDanteClockMaster(srcIP)
}

func (n *Nodes) UpdateDante(name string, ip net.IP) {
	if n.t.DebugDante {
		log.Printf("[dante] mdns response: %s -> %s", name, ip)
	}
	n.Update(nil, nil, []net.IP{ip}, "", name, "dante")
}
