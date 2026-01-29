package tendrils

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/gopatchy/sacn"
)

func (t *Tendrils) startSACNDiscoveryListener(ctx context.Context, iface net.Interface) {
	receiver, err := sacn.NewReceiver("")
	if err != nil {
		log.Printf("[ERROR] failed to create sacn receiver: %v", err)
		return
	}
	defer receiver.Stop()

	if err := receiver.JoinDiscovery(&iface); err != nil {
		log.Printf("[ERROR] failed to join sacn discovery multicast on %s: %v", iface.Name, err)
		return
	}

	if t.DebugSACN {
		log.Printf("[sacn] listening for discovery on %s", iface.Name)
	}

	receiver.SetHandler(func(src *net.UDPAddr, pkt interface{}) {
		if disc, ok := pkt.(*sacn.DiscoveryPacket); ok {
			t.handleSACNDiscoveryPacket(src.IP, disc)
		}
	})

	receiver.Start()
	<-ctx.Done()
}

func (t *Tendrils) handleSACNDiscoveryPacket(srcIP net.IP, pkt *sacn.DiscoveryPacket) {
	if t.DebugSACN {
		log.Printf("[sacn] discovery from %q cid=%s ip=%s universes=%v", pkt.SourceName, sacn.FormatCID(pkt.CID), srcIP, pkt.Universes)
	}

	if srcIP != nil && pkt.SourceName != "" {
		t.nodes.Update(nil, nil, []net.IP{srcIP}, "", pkt.SourceName, "sacn")
	}

	node := t.nodes.GetByIP(srcIP)
	if node != nil {
		intUniverses := make([]int, len(pkt.Universes))
		for i, u := range pkt.Universes {
			intUniverses[i] = int(u)
		}
		t.nodes.UpdateSACN(node, intUniverses)
	}
	t.NotifyUpdate()
}

func (n *Nodes) UpdateSACN(node *Node, outputs []int) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if node.SACNOutputs == nil {
		node.SACNOutputs = SACNUniverseSet{}
	}

	for _, u := range outputs {
		node.SACNOutputs.Add(SACNUniverse(u))
	}
}

func (n *Nodes) expireSACN() {
	for _, node := range n.nodes {
		if node.SACNOutputs != nil {
			node.SACNOutputs.Expire(60 * time.Second)
		}
	}
}

func (n *Nodes) mergeSACN(keep, merge *Node) {
	if merge.SACNOutputs == nil {
		return
	}
	if keep.SACNOutputs == nil {
		keep.SACNOutputs = SACNUniverseSet{}
	}
	for u, lastSeen := range merge.SACNOutputs {
		if existing, ok := keep.SACNOutputs[u]; !ok || lastSeen.After(existing) {
			keep.SACNOutputs[u] = lastSeen
		}
	}
}
