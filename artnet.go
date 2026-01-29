package tendrils

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/fvbommel/sortorder"
	"github.com/gopatchy/artnet"
)

func (t *Tendrils) startArtNetListener(ctx context.Context) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: artnet.Port})
	if err != nil {
		log.Printf("[ERROR] failed to listen artnet: %v", err)
		return
	}
	defer conn.Close()

	t.artnetConn = conn

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

		t.handleArtNetPacket(src, buf[:n])
	}
}

func (t *Tendrils) startArtNetPoller(ctx context.Context, iface net.Interface) {
	srcIP, broadcast := getInterfaceIPv4(iface)
	if srcIP == nil || broadcast == nil {
		return
	}

	sendConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: srcIP, Port: 0})
	if err != nil {
		log.Printf("[ERROR] failed to create artnet send socket on %s: %v", iface.Name, err)
		return
	}
	defer sendConn.Close()

	go t.listenArtNetReplies(ctx, sendConn, iface.Name)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	t.sendArtPoll(sendConn, broadcast, iface.Name)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.sendArtPoll(sendConn, broadcast, iface.Name)
		}
	}
}

func (t *Tendrils) listenArtNetReplies(ctx context.Context, conn *net.UDPConn, ifaceName string) {
	buf := make([]byte, 1024)
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
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}

		t.handleArtNetPacket(src, buf[:n])
	}
}

func (t *Tendrils) handleArtNetPacket(src *net.UDPAddr, data []byte) {
	opCode, pkt, err := artnet.ParsePacket(data)
	if err != nil {
		return
	}

	switch opCode {
	case artnet.OpPollReply:
		if reply, ok := pkt.(*artnet.PollReplyPacket); ok {
			t.handleArtPollReply(src.IP, reply)
		}
	}
}

func (t *Tendrils) handleArtPollReply(srcIP net.IP, pkt *artnet.PollReplyPacket) {
	ip := pkt.IP()
	mac := pkt.MACAddr()
	shortName := pkt.GetShortName()
	longName := pkt.GetLongName()

	var inputs, outputs []int
	for _, u := range pkt.InputUniverses() {
		inputs = append(inputs, int(u))
	}
	for _, u := range pkt.OutputUniverses() {
		outputs = append(outputs, int(u))
	}

	if t.DebugArtNet {
		log.Printf("[artnet] %s %s short=%q long=%q in=%v out=%v", ip, mac, shortName, longName, inputs, outputs)
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

func (t *Tendrils) sendArtPoll(conn *net.UDPConn, broadcast net.IP, ifaceName string) {
	packet := artnet.BuildPollPacket()

	_, err := conn.WriteToUDP(packet, &net.UDPAddr{IP: broadcast, Port: artnet.Port})
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

func containsInt(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

func (n *Nodes) UpdateArtNet(node *Node, inputs, outputs []int) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if node.ArtNetInputs == nil {
		node.ArtNetInputs = ArtNetUniverseSet{}
	}
	if node.ArtNetOutputs == nil {
		node.ArtNetOutputs = ArtNetUniverseSet{}
	}

	for _, u := range inputs {
		node.ArtNetInputs.Add(ArtNetUniverse(u))
	}
	for _, u := range outputs {
		node.ArtNetOutputs.Add(ArtNetUniverse(u))
	}
}

func (n *Nodes) expireArtNet() {
	for _, node := range n.nodes {
		if node.ArtNetInputs != nil {
			node.ArtNetInputs.Expire(60 * time.Second)
		}
		if node.ArtNetOutputs != nil {
			node.ArtNetOutputs.Expire(60 * time.Second)
		}
	}
}

func (n *Nodes) mergeArtNet(keep, merge *Node) {
	if merge.ArtNetInputs != nil {
		if keep.ArtNetInputs == nil {
			keep.ArtNetInputs = ArtNetUniverseSet{}
		}
		for u, lastSeen := range merge.ArtNetInputs {
			if existing, ok := keep.ArtNetInputs[u]; !ok || lastSeen.After(existing) {
				keep.ArtNetInputs[u] = lastSeen
			}
		}
	}
	if merge.ArtNetOutputs != nil {
		if keep.ArtNetOutputs == nil {
			keep.ArtNetOutputs = ArtNetUniverseSet{}
		}
		for u, lastSeen := range merge.ArtNetOutputs {
			if existing, ok := keep.ArtNetOutputs[u]; !ok || lastSeen.After(existing) {
				keep.ArtNetOutputs[u] = lastSeen
			}
		}
	}
}

func (n *Nodes) logArtNet() {
	inputUniverses := map[ArtNetUniverse][]string{}
	outputUniverses := map[ArtNetUniverse][]string{}

	for _, node := range n.nodes {
		if len(node.ArtNetInputs) == 0 && len(node.ArtNetOutputs) == 0 {
			continue
		}
		name := node.DisplayName()
		if name == "" {
			name = "??"
		}
		for u := range node.ArtNetInputs {
			inputUniverses[u] = append(inputUniverses[u], name)
		}
		for u := range node.ArtNetOutputs {
			outputUniverses[u] = append(outputUniverses[u], name)
		}
	}

	if len(inputUniverses) == 0 && len(outputUniverses) == 0 {
		return
	}

	seen := map[ArtNetUniverse]bool{}
	var allUniverses []ArtNetUniverse
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
	sort.Slice(allUniverses, func(i, j int) bool { return allUniverses[i] < allUniverses[j] })

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
		log.Printf("[sigusr1]   artnet:%d (%s) %s", u, u.String(), strings.Join(parts, "; "))
	}
}
