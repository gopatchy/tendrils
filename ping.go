package tendrils

import (
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type pendingPing struct {
	ip       string
	response chan bool
}

type PingManager struct {
	mu       sync.Mutex
	conn     *icmp.PacketConn
	pending  map[uint16]*pendingPing
	nextID   uint16
	minID    uint16
	failures map[string]int
}

const pingFailureThreshold = 5

func NewPingManager() *PingManager {
	pm := &PingManager{
		pending:  map[uint16]*pendingPing{},
		nextID:   1000,
		minID:    1000,
		failures: map[string]int{},
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return pm
	}
	pm.conn = conn

	go pm.readLoop()

	return pm
}

func (pm *PingManager) readLoop() {
	buf := make([]byte, 1500)
	for {
		n, peer, err := pm.conn.ReadFrom(buf)
		if err != nil {
			return
		}

		msg, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}

		if msg.Type != ipv4.ICMPTypeEchoReply {
			continue
		}

		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		ipAddr, ok := peer.(*net.IPAddr)
		if !ok {
			continue
		}

		pm.mu.Lock()
		id := uint16(echo.ID)
		if p, exists := pm.pending[id]; exists {
			if p.ip == ipAddr.IP.String() {
				select {
				case p.response <- true:
				default:
					log.Printf("[ping] late response from %s (channel full)", ipAddr.IP)
				}
			}
		} else if id >= pm.minID {
			log.Printf("[ping] late response from %s (id %d expired)", ipAddr.IP, echo.ID)
		}
		pm.mu.Unlock()
	}
}

func (pm *PingManager) Ping(ipStr string, timeout time.Duration) bool {
	if pm.conn == nil {
		return false
	}

	pm.mu.Lock()
	pm.nextID++
	id := pm.nextID
	p := &pendingPing{
		ip:       ipStr,
		response: make(chan bool, 1),
	}
	pm.pending[id] = p
	pm.mu.Unlock()

	defer func() {
		pm.mu.Lock()
		delete(pm.pending, id)
		pm.mu.Unlock()
	}()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   int(id),
			Seq:  1,
			Data: []byte("tendrils"),
		},
	}
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return false
	}

	ip := net.ParseIP(ipStr)
	_, err = pm.conn.WriteTo(msgBytes, &net.IPAddr{IP: ip})
	if err != nil {
		return false
	}

	select {
	case <-p.response:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (t *Tendrils) pingNode(node *Node) {
	t.nodes.mu.RLock()
	var ips []string
	nodeName := node.DisplayName()
	nodeID := node.ID
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

	anyReachable := false
	for _, ipStr := range ips {
		if t.ping.Ping(ipStr, 2*time.Second) {
			anyReachable = true
			break
		}
	}

	t.ping.mu.Lock()
	if anyReachable {
		t.ping.failures[nodeID] = 0
		t.ping.mu.Unlock()
		if node.SetUnreachable(false) {
			log.Printf("[ping] %s is now reachable", nodeName)
		}
	} else {
		t.ping.failures[nodeID]++
		failures := t.ping.failures[nodeID]
		t.ping.mu.Unlock()
		if failures >= pingFailureThreshold {
			if node.SetUnreachable(true) {
				log.Printf("[ping] %s is now unreachable", nodeName)
			}
		}
	}
}
