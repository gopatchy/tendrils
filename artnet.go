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

type artnetHandler struct {
	t         *Tendrils
	discovery *artnet.Discovery
}

func (h *artnetHandler) HandleDMX(src *net.UDPAddr, pkt *artnet.DMXPacket) {}

func (h *artnetHandler) HandlePoll(src *net.UDPAddr, pkt *artnet.PollPacket) {
	h.discovery.HandlePoll(src)
}

func (h *artnetHandler) HandlePollReply(src *net.UDPAddr, pkt *artnet.PollReplyPacket) {
	h.discovery.HandlePollReply(src, pkt)
}

func (h *artnetHandler) HandleTodData(src *net.UDPAddr, pkt *artnet.TodDataPacket) {
	h.discovery.HandleTodData(src, pkt)
}

func (t *Tendrils) startArtNet(ctx context.Context, iface net.Interface) {
	srcIP, broadcast := getInterfaceIPv4(iface)
	if srcIP == nil || broadcast == nil {
		return
	}

	sender, err := artnet.NewInterfaceSender(iface.Name)
	if err != nil {
		log.Printf("[ERROR] failed to create artnet sender for %s: %v", iface.Name, err)
		return
	}

	discovery := artnet.NewDiscovery(sender, srcIP, broadcast, iface.HardwareAddr, "", "", nil, nil)
	discovery.SetOnChange(func(node *artnet.Node) {
		t.handleArtNetNode(node)
	})

	handler := &artnetHandler{t: t, discovery: discovery}

	receiver, err := artnet.NewInterfaceReceiver(iface.Name, handler)
	if err != nil {
		log.Printf("[ERROR] failed to create artnet receiver for %s: %v", iface.Name, err)
		sender.Close()
		return
	}

	discovery.SetReceiver(receiver)
	receiver.Start()
	discovery.Start()

	<-ctx.Done()

	discovery.Stop()
	receiver.Stop()
	sender.Close()
}

func (t *Tendrils) handleArtNetNode(node *artnet.Node) {
	ip := node.IP
	mac := node.MAC
	shortName := node.ShortName
	longName := node.LongName

	var inputs, outputs []int
	for _, u := range node.Inputs {
		inputs = append(inputs, int(u))
	}
	for _, u := range node.Outputs {
		outputs = append(outputs, int(u))
	}

	rdmUIDs := map[int][]string{}
	for u, uids := range node.RDMUIDs {
		var uidStrs []string
		for _, uid := range uids {
			uidStrs = append(uidStrs, uid.String())
		}
		if len(uidStrs) > 0 {
			rdmUIDs[int(u)] = uidStrs
		}
	}

	if t.DebugArtNet {
		log.Printf("[artnet] %s %s short=%q long=%q in=%v out=%v rdm=%v", ip, mac, shortName, longName, inputs, outputs, rdmUIDs)
	}

	name := longName
	if name == "" {
		name = shortName
	}
	if name != "" {
		t.nodes.Update(nil, mac, []net.IP{ip}, "", name, "artnet")
	}

	n := t.nodes.GetByIP(ip)
	if n == nil && mac != nil {
		n = t.nodes.GetByMAC(mac)
	}
	if n == nil && name != "" {
		n = t.nodes.GetOrCreateByName(name)
	}
	if n != nil {
		t.nodes.UpdateArtNet(n, inputs, outputs)
		t.nodes.UpdateArtNetRDM(n, rdmUIDs)
	}
	t.NotifyUpdate()
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

func (n *Nodes) UpdateArtNetRDM(node *Node, rdmUIDs map[int][]string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if len(rdmUIDs) == 0 {
		return
	}

	if node.ArtNetRDMUIDs == nil {
		node.ArtNetRDMUIDs = map[int][]string{}
	}

	for u, uids := range rdmUIDs {
		node.ArtNetRDMUIDs[u] = uids
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
