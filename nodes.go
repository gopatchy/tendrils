package tendrils

import (
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
)

type Node struct {
	Name string
	IPs  map[string]net.IP
	MACs map[string]net.HardwareAddr
}

func (n *Node) String() string {
	var macs []string
	for _, mac := range n.MACs {
		macs = append(macs, mac.String())
	}
	sort.Strings(macs)

	var ips []string
	for _, ip := range n.IPs {
		ips = append(ips, ip.String())
	}
	sort.Strings(ips)

	name := n.Name
	if name == "" {
		name = "??"
	}

	return fmt.Sprintf("%s {macs=%v ips=%v}", name, macs, ips)
}

type Nodes struct {
	mu       sync.RWMutex
	nodes    map[int]*Node
	ipIndex  map[string]int
	macIndex map[string]int
	nextID   int
	t        *Tendrils
}

func NewNodes(t *Tendrils) *Nodes {
	n := &Nodes{
		nodes:    map[int]*Node{},
		ipIndex:  map[string]int{},
		macIndex: map[string]int{},
		nextID:   1,
		t:        t,
	}

	n.nodes[0] = &Node{
		IPs:  map[string]net.IP{},
		MACs: map[string]net.HardwareAddr{},
	}

	return n
}

func (n *Nodes) Update(ips []net.IP, macs []net.HardwareAddr, source string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if len(ips) == 0 && len(macs) == 0 {
		return
	}

	existingIDs := map[int]bool{}

	for _, ip := range ips {
		if id, exists := n.ipIndex[ip.String()]; exists {
			existingIDs[id] = true
		}
	}

	for _, mac := range macs {
		if id, exists := n.macIndex[mac.String()]; exists {
			existingIDs[id] = true
		}
	}

	var targetID int
	isNew := false
	if len(existingIDs) == 0 {
		targetID = n.nextID
		n.nextID++
		n.nodes[targetID] = &Node{
			IPs:  map[string]net.IP{},
			MACs: map[string]net.HardwareAddr{},
		}
		isNew = true
	} else if len(existingIDs) == 1 {
		for id := range existingIDs {
			targetID = id
		}
	} else {
		var ids []int
		for id := range existingIDs {
			ids = append(ids, id)
		}
		targetID = ids[0]
		var merging []string
		for i := 1; i < len(ids); i++ {
			merging = append(merging, n.nodes[ids[i]].String())
			n.mergeNodes(targetID, ids[i])
		}
		if n.t.LogEvents {
			log.Printf("[merge] %v into %s (via %s)", merging, n.nodes[targetID], source)
		}
	}

	node := n.nodes[targetID]
	var added []string

	for _, ip := range ips {
		ipKey := ip.String()
		if _, exists := node.IPs[ipKey]; !exists {
			added = append(added, "ip="+ipKey)
		}
		node.IPs[ipKey] = ip
		n.ipIndex[ipKey] = targetID
	}

	for _, mac := range macs {
		macKey := mac.String()
		if _, exists := node.MACs[macKey]; !exists {
			added = append(added, "mac="+macKey)
		}
		node.MACs[macKey] = mac
		n.macIndex[macKey] = targetID
	}

	if len(added) > 0 && n.t.LogEvents {
		if isNew {
			log.Printf("[add] %s %v (via %s)", node, added, source)
		} else {
			log.Printf("[update] %s +%v (via %s)", node, added, source)
		}
	}
}

func (n *Nodes) mergeNodes(keepID, mergeID int) {
	keep := n.nodes[keepID]
	merge := n.nodes[mergeID]

	for ipKey, ip := range merge.IPs {
		keep.IPs[ipKey] = ip
		n.ipIndex[ipKey] = keepID
	}

	for macKey, mac := range merge.MACs {
		keep.MACs[macKey] = mac
		n.macIndex[macKey] = keepID
	}

	delete(n.nodes, mergeID)
}

func (n *Nodes) GetByIP(ipv4 net.IP) *Node {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if id, exists := n.ipIndex[ipv4.String()]; exists {
		return n.nodes[id]
	}
	return nil
}

func (n *Nodes) GetByMAC(mac net.HardwareAddr) *Node {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if id, exists := n.macIndex[mac.String()]; exists {
		return n.nodes[id]
	}
	return nil
}

func (n *Nodes) SetName(mac net.HardwareAddr, name string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if id, exists := n.macIndex[mac.String()]; exists {
		node := n.nodes[id]
		if node.Name == "" {
			node.Name = name
		}
	}
}

func (n *Nodes) All() []*Node {
	n.mu.RLock()
	defer n.mu.RUnlock()

	result := make([]*Node, 0, len(n.nodes))
	for _, node := range n.nodes {
		result = append(result, node)
	}
	return result
}
