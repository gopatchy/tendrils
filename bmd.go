package tendrils

import (
	"context"
	"log"
	"net"
	"time"
)

func (t *Tendrils) listenBMD(ctx context.Context, iface net.Interface) {
	addrs, err := iface.Addrs()
	if err != nil {
		return
	}

	var srcIP net.IP
	var broadcast net.IP
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			srcIP = ipnet.IP.To4()
			mask := ipnet.Mask
			broadcast = make(net.IP, 4)
			for i := 0; i < 4; i++ {
				broadcast[i] = srcIP[i] | ^mask[i]
			}
			break
		}
	}
	if srcIP == nil {
		return
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: srcIP, Port: 0})
	if err != nil {
		return
	}
	defer conn.Close()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	t.sendATEMDiscovery(conn, broadcast, iface.Name)

	go t.receiveATEMResponses(ctx, conn, iface.Name)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.sendATEMDiscovery(conn, broadcast, iface.Name)
		}
	}
}

func (t *Tendrils) sendATEMDiscovery(conn *net.UDPConn, broadcast net.IP, ifaceName string) {
	// ATEM protocol hello packet
	// Flag 0x10 (hello), length 20 bytes
	packet := []byte{
		0x10, 0x14, // Flags (0x10 = hello) + length (20 = 0x14)
		0x00, 0x00, // Session ID
		0x00, 0x00, // Ack number
		0x00, 0x00, // Local sequence
		0x00, 0x00, // Remote sequence
		0x00, 0x00, // Unknown
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Client hello data
	}

	conn.WriteToUDP(packet, &net.UDPAddr{IP: broadcast, Port: 9910})

	if t.DebugBMD {
		log.Printf("[bmd] %s: sent atem discovery to %s", ifaceName, broadcast)
	}
}

func (t *Tendrils) receiveATEMResponses(ctx context.Context, conn *net.UDPConn, ifaceName string) {
	seen := map[string]bool{}
	buf := make([]byte, 2048)
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

		if n < 12 {
			continue
		}

		ipKey := src.IP.String()
		if seen[ipKey] {
			continue
		}
		seen[ipKey] = true

		if t.DebugBMD {
			log.Printf("[bmd] %s: atem at %s", ifaceName, src.IP)
		}

		t.nodes.Update(nil, nil, []net.IP{src.IP}, "", "atem", "bmd")
	}
}
