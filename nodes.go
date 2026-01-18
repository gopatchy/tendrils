package tendrils

import (
	"fmt"
	"log"
	"net"
	"sort"
	"sync"

	"github.com/fvbommel/sortorder"
)

type Interface struct {
	Name string
	MAC  net.HardwareAddr
	IPs  map[string]net.IP
}

func (i *Interface) String() string {
	var ips []string
	for _, ip := range i.IPs {
		ips = append(ips, ip.String())
	}
	sort.Strings(ips)

	var parts []string
	parts = append(parts, i.MAC.String())
	if i.Name != "" {
		parts = append(parts, fmt.Sprintf("(%s)", i.Name))
	}
	if len(ips) > 0 {
		parts = append(parts, fmt.Sprintf("%v", ips))
	}

	result := parts[0]
	for _, p := range parts[1:] {
		result += " " + p
	}
	return result
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
	sort.Slice(ifaces, func(i, j int) bool { return sortorder.NaturalLess(ifaces[i], ifaces[j]) })

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
	targetID := -1
	isNew := false

	if id, exists := n.macIndex[macKey]; exists {
		if _, nodeExists := n.nodes[id]; nodeExists {
			targetID = id
		} else {
			delete(n.macIndex, macKey)
		}
	}

	if targetID == -1 {
		targetID = n.nextID
		n.nextID++
		n.nodes[targetID] = &Node{
			Interfaces: map[string]*Interface{},
		}
		isNew = true
	}

	node := n.nodes[targetID]

	added := n.updateNodeInterface(node, targetID, mac, ips, ifaceName)

	if nodeName != "" && node.Name == "" {
		node.Name = nodeName
	}

	if len(added) > 0 {
		if n.t.LogEvents {
			if isNew {
				log.Printf("[add] %s %v (via %s)", node, added, source)
			} else {
				log.Printf("[update] %s +%v (via %s)", node, added, source)
			}
		}
		if n.t.LogNodes {
			n.logNode(node)
		}
	}
}

func (n *Nodes) updateNodeInterface(node *Node, nodeID int, mac net.HardwareAddr, ips []net.IP, ifaceName string) []string {
	macKey := mac.String()
	var added []string

	ifaceKey := macKey
	if ifaceName != "" {
		ifaceKey = ifaceName
	}

	iface, exists := node.Interfaces[ifaceKey]
	if !exists {
		if ifaceName != "" {
			if oldIface, oldExists := node.Interfaces[macKey]; oldExists && oldIface.MAC.String() == macKey {
				iface = oldIface
				iface.Name = ifaceName
				delete(node.Interfaces, macKey)
				node.Interfaces[ifaceKey] = iface
				added = append(added, "iface="+ifaceKey)
				exists = true
			}
		} else {
			for _, existing := range node.Interfaces {
				if existing.MAC.String() == macKey {
					iface = existing
					exists = true
					break
				}
			}
		}
	}
	if !exists {
		iface = &Interface{
			Name: ifaceName,
			MAC:  mac,
			IPs:  map[string]net.IP{},
		}
		node.Interfaces[ifaceKey] = iface
		added = append(added, "iface="+ifaceKey)
	}

	if _, exists := n.macIndex[macKey]; !exists {
		n.macIndex[macKey] = nodeID
	}

	for _, ip := range ips {
		ipKey := ip.String()
		if _, exists := iface.IPs[ipKey]; !exists {
			added = append(added, "ip="+ipKey)
		}
		iface.IPs[ipKey] = ip
		n.ipIndex[ipKey] = nodeID
	}

	return added
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

	if n.t.LogNodes {
		n.logNode(n.nodes[targetID])
	}
}

func (n *Nodes) mergeNodes(keepID, mergeID int) {
	keep := n.nodes[keepID]
	merge := n.nodes[mergeID]

	if keep == nil || merge == nil {
		return
	}

	if merge.Name != "" && keep.Name == "" {
		keep.Name = merge.Name
	}

	for _, iface := range merge.Interfaces {
		var ips []net.IP
		for _, ip := range iface.IPs {
			ips = append(ips, ip)
		}
		n.updateNodeInterface(keep, keepID, iface.MAC, ips, iface.Name)
		n.macIndex[iface.MAC.String()] = keepID
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

func (n *Nodes) logNode(node *Node) {
	name := node.Name
	if name == "" {
		name = "??"
	}
	log.Printf("[node] %s", name)

	var ifaceKeys []string
	for ifaceKey := range node.Interfaces {
		ifaceKeys = append(ifaceKeys, ifaceKey)
	}
	sort.Slice(ifaceKeys, func(i, j int) bool { return sortorder.NaturalLess(ifaceKeys[i], ifaceKeys[j]) })

	for _, ifaceKey := range ifaceKeys {
		iface := node.Interfaces[ifaceKey]
		log.Printf("[node]   %s", iface)
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
