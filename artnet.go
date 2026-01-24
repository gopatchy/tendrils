package tendrils

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fvbommel/sortorder"
)

const (
	artNetPort      = 6454
	artNetID        = "Art-Net\x00"
	opPoll          = 0x2000
	opPollReply     = 0x2100
	protocolVersion = 14
)

type ArtNetNode struct {
	TypeID   string    `json:"typeid"`
	Node     *Node     `json:"node"`
	Inputs   []int     `json:"inputs,omitempty"`
	Outputs  []int     `json:"outputs,omitempty"`
	LastSeen time.Time `json:"last_seen"`
}

func (t *Tendrils) listenArtNet(ctx context.Context, iface net.Interface) {
	srcIP, _ := getInterfaceIPv4(iface)
	if srcIP == nil {
		return
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: srcIP, Port: artNetPort})
	if err != nil {
		log.Printf("[ERROR] failed to listen artnet on %s: %v", iface.Name, err)
		return
	}
	defer conn.Close()

	go t.runArtNetPoller(ctx, iface, conn)

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

		t.handleArtNetPacket(iface.Name, src.IP, buf[:n])
	}
}

func (t *Tendrils) handleArtNetPacket(ifaceName string, srcIP net.IP, data []byte) {
	if len(data) < 12 {
		return
	}

	if string(data[:8]) != artNetID {
		return
	}

	opcode := binary.LittleEndian.Uint16(data[8:10])

	switch opcode {
	case opPollReply:
		t.handleArtPollReply(ifaceName, srcIP, data)
	}
}

func (t *Tendrils) handleArtPollReply(ifaceName string, srcIP net.IP, data []byte) {
	if len(data) < 207 {
		return
	}

	ip := net.IPv4(data[10], data[11], data[12], data[13])

	var mac net.HardwareAddr
	if len(data) >= 207 {
		mac = net.HardwareAddr(data[201:207])
	}

	shortName := strings.TrimRight(string(data[26:44]), "\x00")
	longName := strings.TrimRight(string(data[44:108]), "\x00")

	netSwitch := int(data[18])
	subSwitch := int(data[19])

	numPorts := int(data[173])
	if numPorts > 4 {
		numPorts = 4
	}

	var inputs, outputs []int
	for i := 0; i < numPorts; i++ {
		portType := data[174+i]
		swIn := int(data[186+i])
		swOut := int(data[190+i])

		universe := netSwitch<<8 | subSwitch<<4

		if portType&0x40 != 0 {
			inputs = append(inputs, universe|swIn)
		}
		if portType&0x80 != 0 {
			outputs = append(outputs, universe|swOut)
		}
	}

	if t.DebugArtNet {
		log.Printf("[artnet] %s: %s %s short=%q long=%q numPorts=%d portTypes=%v in=%v out=%v", ifaceName, ip, mac, shortName, longName, numPorts, data[174:178], inputs, outputs)
	}

	name := longName
	if name == "" {
		name = shortName
	}
	if name != "" {
		t.nodes.Update(nil, mac, []net.IP{ip}, "", name, "artnet")
	}

	node := t.nodes.GetByIP(ip)
	if node == nil && mac != nil {
		node = t.nodes.GetByMAC(mac)
	}
	if node == nil && name != "" {
		node = t.nodes.GetOrCreateByName(name)
	}
	if node != nil {
		t.nodes.UpdateArtNet(node, inputs, outputs)
	}
}

func (t *Tendrils) runArtNetPoller(ctx context.Context, iface net.Interface, conn *net.UDPConn) {
	_, broadcast := getInterfaceIPv4(iface)
	if broadcast == nil {
		return
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	t.sendArtPoll(conn, broadcast, iface.Name)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.sendArtPoll(conn, broadcast, iface.Name)
		}
	}
}

func (t *Tendrils) sendArtPoll(conn *net.UDPConn, broadcast net.IP, ifaceName string) {
	packet := make([]byte, 14)
	copy(packet[0:8], artNetID)
	binary.LittleEndian.PutUint16(packet[8:10], opPoll)
	binary.LittleEndian.PutUint16(packet[10:12], protocolVersion)
	packet[12] = 0x00
	packet[13] = 0x00

	_, err := conn.WriteToUDP(packet, &net.UDPAddr{IP: broadcast, Port: artNetPort})
	if err != nil {
		if t.DebugArtNet {
			log.Printf("[artnet] %s: failed to send poll: %v", ifaceName, err)
		}
		return
	}

	if t.DebugArtNet {
		log.Printf("[artnet] %s: sent poll to %s", ifaceName, broadcast)
	}
}

type ArtNetNodes struct {
	mu    sync.RWMutex
	nodes map[*Node]*ArtNetNode
}

func NewArtNetNodes() *ArtNetNodes {
	return &ArtNetNodes{
		nodes: map[*Node]*ArtNetNode{},
	}
}

func (a *ArtNetNodes) Update(node *Node, inputs, outputs []int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	existing, exists := a.nodes[node]
	if exists {
		for _, u := range inputs {
			if !containsInt(existing.Inputs, u) {
				existing.Inputs = append(existing.Inputs, u)
			}
		}
		for _, u := range outputs {
			if !containsInt(existing.Outputs, u) {
				existing.Outputs = append(existing.Outputs, u)
			}
		}
		existing.LastSeen = time.Now()
	} else {
		a.nodes[node] = &ArtNetNode{
			TypeID:   newTypeID("artnetnode"),
			Node:     node,
			Inputs:   inputs,
			Outputs:  outputs,
			LastSeen: time.Now(),
		}
	}
}

func containsInt(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

func (a *ArtNetNodes) ReplaceNode(oldNode, newNode *Node) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if artNode, exists := a.nodes[oldNode]; exists {
		delete(a.nodes, oldNode)
		if existing, hasNew := a.nodes[newNode]; hasNew {
			for _, u := range artNode.Inputs {
				if !containsInt(existing.Inputs, u) {
					existing.Inputs = append(existing.Inputs, u)
				}
			}
			for _, u := range artNode.Outputs {
				if !containsInt(existing.Outputs, u) {
					existing.Outputs = append(existing.Outputs, u)
				}
			}
		} else {
			artNode.Node = newNode
			a.nodes[newNode] = artNode
		}
	}
}

func (a *ArtNetNodes) Expire() {
	a.mu.Lock()
	defer a.mu.Unlock()
	expireTime := time.Now().Add(-60 * time.Second)
	for nodePtr, artNode := range a.nodes {
		if artNode.LastSeen.Before(expireTime) {
			delete(a.nodes, nodePtr)
		}
	}
}

func (a *ArtNetNodes) GetAll() []*ArtNetNode {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([]*ArtNetNode, 0, len(a.nodes))
	for _, node := range a.nodes {
		result = append(result, node)
	}
	return result
}

func (a *ArtNetNodes) LogAll() {
	a.Expire()

	a.mu.RLock()
	defer a.mu.RUnlock()

	if len(a.nodes) == 0 {
		return
	}

	var artNodes []*ArtNetNode
	for _, artNode := range a.nodes {
		artNodes = append(artNodes, artNode)
	}
	sort.Slice(artNodes, func(i, j int) bool {
		return sortorder.NaturalLess(artNodes[i].Node.DisplayName(), artNodes[j].Node.DisplayName())
	})

	inputUniverses := map[int][]string{}
	outputUniverses := map[int][]string{}

	for _, artNode := range artNodes {
		name := artNode.Node.DisplayName()
		if name == "" {
			name = "??"
		}
		for _, u := range artNode.Inputs {
			inputUniverses[u] = append(inputUniverses[u], name)
		}
		for _, u := range artNode.Outputs {
			outputUniverses[u] = append(outputUniverses[u], name)
		}
	}

	var allUniverses []int
	seen := map[int]bool{}
	for u := range inputUniverses {
		if !seen[u] {
			allUniverses = append(allUniverses, u)
			seen[u] = true
		}
	}
	for u := range outputUniverses {
		if !seen[u] {
			allUniverses = append(allUniverses, u)
			seen[u] = true
		}
	}
	sort.Ints(allUniverses)

	log.Printf("[sigusr1] ================ %d artnet universes ================", len(allUniverses))
	for _, u := range allUniverses {
		ins := inputUniverses[u]
		outs := outputUniverses[u]
		var parts []string
		if len(ins) > 0 {
			sort.Slice(ins, func(i, j int) bool { return sortorder.NaturalLess(ins[i], ins[j]) })
			parts = append(parts, fmt.Sprintf("in: %s", strings.Join(ins, ", ")))
		}
		if len(outs) > 0 {
			sort.Slice(outs, func(i, j int) bool { return sortorder.NaturalLess(outs[i], outs[j]) })
			parts = append(parts, fmt.Sprintf("out: %s", strings.Join(outs, ", ")))
		}
		net := (u >> 8) & 0x7f
		subnet := (u >> 4) & 0x0f
		universe := u & 0x0f
		log.Printf("[sigusr1]   artnet:%d (%d/%d/%d) %s", u, net, subnet, universe, strings.Join(parts, "; "))
	}
}

func (n *Nodes) UpdateArtNet(node *Node, inputs, outputs []int) {
	n.t.artnet.Update(node, inputs, outputs)
}
