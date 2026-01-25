package tendrils

import (
	"context"
	"log"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func (t *Tendrils) pingBroadcast(ctx context.Context, iface net.Interface) {
	_, broadcast := getInterfaceIPv4(iface)
	if broadcast == nil {
		return
	}

	t.sendBroadcastPing(broadcast, iface.Name)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.sendBroadcastPing(broadcast, iface.Name)
		}
	}
}

func (t *Tendrils) sendBroadcastPing(broadcast net.IP, ifaceName string) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		if t.DebugARP {
			log.Printf("[broadcast] %s: failed to create icmp socket: %v", ifaceName, err)
		}
		return
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   1,
			Seq:  1,
			Data: []byte("tendrils"),
		},
	}
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return
	}

	_, err = conn.WriteTo(msgBytes, &net.IPAddr{IP: broadcast})
	if err != nil {
		if t.DebugARP {
			log.Printf("[broadcast] %s: failed to send ping to %s: %v", ifaceName, broadcast, err)
		}
		return
	}

	if t.DebugARP {
		log.Printf("[broadcast] %s: sent ping to %s", ifaceName, broadcast)
	}
}
