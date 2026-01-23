package tendrils

import (
	"context"
	"log"
	"net"
	"time"
)

func (t *Tendrils) listenDante(ctx context.Context, iface net.Interface) {
	go t.listenPTP(ctx, iface)
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
