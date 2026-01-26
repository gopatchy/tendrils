package tendrils

import (
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func (t *Tendrils) pingNode(node *Node) {
	t.nodes.mu.RLock()
	var ips []string
	for _, iface := range node.Interfaces {
		for ipStr := range iface.IPs {
			ip := net.ParseIP(ipStr)
			if ip != nil && ip.To4() != nil {
				ips = append(ips, ipStr)
			}
		}
	}
	t.nodes.mu.RUnlock()

	if len(ips) == 0 {
		return
	}

	for _, ipStr := range ips {
		reachable := t.pingIP(ipStr)
		if reachable {
			t.errors.ClearUnreachable(node, ipStr)
		} else {
			t.errors.SetUnreachable(node, ipStr)
		}
	}
}

func (t *Tendrils) pingIP(ipStr string) bool {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(500 * time.Millisecond))

	ip := net.ParseIP(ipStr)
	seq := uint16(time.Now().UnixNano() & 0xFFFF)

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   int(seq),
			Seq:  1,
			Data: []byte("tendrils"),
		},
	}
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return false
	}

	_, err = conn.WriteTo(msgBytes, &net.IPAddr{IP: ip})
	if err != nil {
		return false
	}

	buf := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			return false
		}

		parsed, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}

		if parsed.Type == ipv4.ICMPTypeEchoReply {
			if ipAddr, ok := peer.(*net.IPAddr); ok {
				if ipAddr.IP.String() == ipStr {
					return true
				}
			}
		}
	}
}
