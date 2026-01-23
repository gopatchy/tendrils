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
	artNetPort     = 6454
	artNetID       = "Art-Net\x00"
	opPoll         = 0x2000
	opPollReply    = 0x2100
	protocolVersion = 14
)

type ArtNetNode struct {
	IP        net.IP
	MAC       net.HardwareAddr
	ShortName string
	LongName  string
	Inputs    []int
	Outputs   []int
	LastSeen  time.Time
}

func (t *Tendrils) listenArtNet(ctx context.Context, iface net.Interface) {
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

	node := &ArtNetNode{
		IP:        ip,
		MAC:       mac,
		ShortName: shortName,
		LongName:  longName,
		Inputs:    inputs,
		Outputs:   outputs,
		LastSeen:  time.Now(),
	}

	t.nodes.UpdateArtNet(node)

	name := longName
	if name == "" {
		name = shortName
	}
	if name != "" {
		t.nodes.Update(nil, mac, []net.IP{ip}, "", name, "artnet")
	}
}

func (t *Tendrils) runArtNetPoller(ctx context.Context, iface net.Interface, conn *net.UDPConn) {
	addrs, err := iface.Addrs()
	if err != nil {
		return
	}

	var broadcast net.IP
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			ip := ipnet.IP.To4()
			mask := ipnet.Mask
			broadcast = make(net.IP, 4)
			for i := 0; i < 4; i++ {
				broadcast[i] = ip[i] | ^mask[i]
			}
			break
		}
	}
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
	nodes map[string]*ArtNetNode
}

func NewArtNetNodes() *ArtNetNodes {
	return &ArtNetNodes{
		nodes: map[string]*ArtNetNode{},
	}
}

func (a *ArtNetNodes) Update(node *ArtNetNode) {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := node.IP.String()

	existing, exists := a.nodes[key]
	if exists {
		for _, u := range node.Inputs {
			if !containsInt(existing.Inputs, u) {
				existing.Inputs = append(existing.Inputs, u)
			}
		}
		for _, u := range node.Outputs {
			if !containsInt(existing.Outputs, u) {
				existing.Outputs = append(existing.Outputs, u)
			}
		}
		existing.LastSeen = node.LastSeen
		if node.ShortName != "" {
			existing.ShortName = node.ShortName
		}
		if node.LongName != "" {
			existing.LongName = node.LongName
		}
	} else {
		a.nodes[key] = node
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

func (a *ArtNetNodes) Expire() {
	a.mu.Lock()
	defer a.mu.Unlock()
	expireTime := time.Now().Add(-60 * time.Second)
	for key, node := range a.nodes {
		if node.LastSeen.Before(expireTime) {
			delete(a.nodes, key)
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

	var nodes []*ArtNetNode
	for _, node := range a.nodes {
		nodes = append(nodes, node)
	}
	sort.Slice(nodes, func(i, j int) bool {
		return sortorder.NaturalLess(nodes[i].LongName, nodes[j].LongName)
	})

	inputUniverses := map[int][]string{}
	outputUniverses := map[int][]string{}

	for _, node := range nodes {
		name := node.LongName
		if name == "" {
			name = node.ShortName
		}
		if name == "" {
			name = node.IP.String()
		}
		for _, u := range node.Inputs {
			inputUniverses[u] = append(inputUniverses[u], name)
		}
		for _, u := range node.Outputs {
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

func (n *Nodes) UpdateArtNet(artNode *ArtNetNode) {
	n.t.artnet.Update(artNode)
}
