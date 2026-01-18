package tendrils

import (
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
)

type Interface struct {
	Name string
	MAC  net.HardwareAddr
	IPs  map[string]net.IP
}

func (i *Interface) String() string {
	name := i.Name
	if name == "" {
		name = "??"
	}

	var ips []string
	for _, ip := range i.IPs {
		ips = append(ips, ip.String())
	}
	sort.Strings(ips)

	if len(ips) == 0 {
		return fmt.Sprintf("%s/%s", name, i.MAC)
	}
	return fmt.Sprintf("%s/%s %v", name, i.MAC, ips)
}

type Node struct {
	Name       string
	Interfaces map[string]*Interface
}

func (n *Node) String() string {
	name := n.Name
	if name == "" {
		name = "??"
	}

	var ifaces []string
	for _, iface := range n.Interfaces {
		ifaces = append(ifaces, iface.String())
	}
	sort.Strings(ifaces)

	return fmt.Sprintf("%s {%v}", name, ifaces)
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
		Interfaces: map[string]*Interface{},
	}

	return n
}

func (n *Nodes) Update(mac net.HardwareAddr, ips []net.IP, ifaceName, nodeName, source string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if mac == nil {
		return
	}

	macKey := mac.String()
	var targetID int
	isNew := false

	if id, exists := n.macIndex[macKey]; exists {
		targetID = id
	} else {
		targetID = n.nextID
		n.nextID++
		n.nodes[targetID] = &Node{
			Interfaces: map[string]*Interface{},
		}
		isNew = true
	}

	node := n.nodes[targetID]
	var added []string

	iface, exists := node.Interfaces[macKey]
	if !exists {
		iface = &Interface{
			MAC: mac,
			IPs: map[string]net.IP{},
		}
		node.Interfaces[macKey] = iface
		n.macIndex[macKey] = targetID
		added = append(added, "mac="+macKey)
	}

	for _, ip := range ips {
		ipKey := ip.String()
		if _, exists := iface.IPs[ipKey]; !exists {
			added = append(added, "ip="+ipKey)
		}
		iface.IPs[ipKey] = ip
		n.ipIndex[ipKey] = targetID
	}

	if ifaceName != "" && iface.Name == "" {
		iface.Name = ifaceName
	}

	if nodeName != "" && node.Name == "" {
		node.Name = nodeName
	}

	if len(added) > 0 && n.t.LogEvents {
		if isNew {
			log.Printf("[add] %s %v (via %s)", node, added, source)
		} else {
			log.Printf("[update] %s +%v (via %s)", node, added, source)
		}
	}
}

func (n *Nodes) Merge(macs []net.HardwareAddr, source string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if len(macs) < 2 {
		return
	}

	existingIDs := map[int]bool{}
	for _, mac := range macs {
		if id, exists := n.macIndex[mac.String()]; exists {
			existingIDs[id] = true
		}
	}

	if len(existingIDs) < 2 {
		return
	}

	var ids []int
	for id := range existingIDs {
		ids = append(ids, id)
	}
	sort.Ints(ids)

	targetID := ids[0]
	for i := 1; i < len(ids); i++ {
		if n.t.LogEvents {
			log.Printf("[merge] %s into %s (via %s)", n.nodes[ids[i]], n.nodes[targetID], source)
		}
		n.mergeNodes(targetID, ids[i])
	}
}

func (n *Nodes) mergeNodes(keepID, mergeID int) {
	keep := n.nodes[keepID]
	merge := n.nodes[mergeID]

	if merge.Name != "" && keep.Name == "" {
		keep.Name = merge.Name
	}

	for macKey, iface := range merge.Interfaces {
		if existing, exists := keep.Interfaces[macKey]; exists {
			for ipKey, ip := range iface.IPs {
				existing.IPs[ipKey] = ip
				n.ipIndex[ipKey] = keepID
			}
			if existing.Name == "" && iface.Name != "" {
				existing.Name = iface.Name
			}
		} else {
			keep.Interfaces[macKey] = iface
			n.macIndex[macKey] = keepID
			for ipKey := range iface.IPs {
				n.ipIndex[ipKey] = keepID
			}
		}
	}

	delete(n.nodes, mergeID)
}

func (n *Nodes) GetByIP(ip net.IP) *Node {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if id, exists := n.ipIndex[ip.String()]; exists {
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

func (n *Nodes) All() []*Node {
	n.mu.RLock()
	defer n.mu.RUnlock()

	result := make([]*Node, 0, len(n.nodes))
	for _, node := range n.nodes {
		result = append(result, node)
	}
	return result
}
