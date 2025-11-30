package tendrils

import (
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
)

type Node struct {
	IPs        map[string]net.IP
	MACs       map[string]net.HardwareAddr
	ParentID   int
	LocalPort  string
	ParentPort string
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

	return fmt.Sprintf("{macs=%v ips=%v}", macs, ips)
}

type Nodes struct {
	mu       sync.RWMutex
	nodes    map[int]*Node
	ipIndex  map[string]int
	macIndex map[string]int
	nextID   int
}

func NewNodes() *Nodes {
	n := &Nodes{
		nodes:    map[int]*Node{},
		ipIndex:  map[string]int{},
		macIndex: map[string]int{},
		nextID:   1,
	}

	n.nodes[0] = &Node{
		IPs:      map[string]net.IP{},
		MACs:     map[string]net.HardwareAddr{},
		ParentID: 0,
	}

	return n
}

func (n *Nodes) Update(ips []net.IP, macs []net.HardwareAddr, parentPort, childPort, source string) {
	n.UpdateWithParent(nil, ips, macs, parentPort, childPort, source)
}

func (n *Nodes) UpdateWithParent(parentIP net.IP, ips []net.IP, macs []net.HardwareAddr, parentPort, childPort, source string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if len(ips) == 0 && len(macs) == 0 {
		return
	}

	parentID := 0
	if parentIP != nil {
		if id, exists := n.ipIndex[parentIP.String()]; exists {
			parentID = id
		}
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
	if len(existingIDs) == 0 {
		targetID = n.nextID
		n.nextID++
		n.nodes[targetID] = &Node{
			IPs:        map[string]net.IP{},
			MACs:       map[string]net.HardwareAddr{},
			ParentID:   parentID,
			LocalPort:  childPort,
			ParentPort: parentPort,
		}
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
		log.Printf("merged nodes %v into %s (via %s)", merging, n.nodes[targetID], source)
	}

	node := n.nodes[targetID]
	var added []string

	if targetID != 0 {
		if node.LocalPort == "" && childPort != "" {
			node.LocalPort = childPort
			added = append(added, "localPort="+childPort)
		}

		if node.ParentPort == "" && parentPort != "" {
			node.ParentPort = parentPort
			added = append(added, "parentPort="+parentPort)
		}
	}

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

	if len(added) > 0 {
		log.Printf("updated %s +%v (via %s)", node, added, source)
		n.mu.Unlock()
		n.LogTree()
		n.mu.Lock()
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

func (n *Nodes) All() []*Node {
	n.mu.RLock()
	defer n.mu.RUnlock()

	result := make([]*Node, 0, len(n.nodes))
	for _, node := range n.nodes {
		result = append(result, node)
	}
	return result
}

func (n *Nodes) LogTree() {
	n.mu.RLock()
	defer n.mu.RUnlock()

	n.logNode(0, "", true)
}

func (n *Nodes) logNode(id int, prefix string, isLast bool) {
	node := n.nodes[id]

	if id == 0 {
		log.Printf("[root] %s", node)
		n.logChildrenByInterface(id, "")
	} else {
		connector := "├──"
		if isLast {
			connector = "└──"
		}

		childPort := node.LocalPort
		if childPort == "" {
			childPort = "??"
		}

		log.Printf("%s%s %s on %s", prefix, connector, childPort, node)

		children := n.getChildren(id)
		for i, childID := range children {
			childIsLast := i == len(children)-1
			childPrefix := prefix
			if isLast {
				childPrefix += "    "
			} else {
				childPrefix += "│   "
			}
			n.logNode(childID, childPrefix, childIsLast)
		}
	}
}

func (n *Nodes) logChildrenByInterface(parentID int, prefix string) {
	children := n.getChildren(parentID)

	byInterface := map[string][]int{}
	for _, childID := range children {
		child := n.nodes[childID]
		iface := child.ParentPort
		if iface == "" {
			iface = "??"
		}
		byInterface[iface] = append(byInterface[iface], childID)
	}

	var interfaces []string
	for iface := range byInterface {
		interfaces = append(interfaces, iface)
	}
	sort.Strings(interfaces)

	for i, iface := range interfaces {
		isLastInterface := i == len(interfaces)-1
		connector := "├──"
		if isLastInterface {
			connector = "└──"
		}

		log.Printf("%s%s %s", prefix, connector, iface)

		nodes := byInterface[iface]
		for j, nodeID := range nodes {
			isLastNode := j == len(nodes)-1
			nodeConnector := "├──"
			if isLastNode {
				nodeConnector = "└──"
			}

			nodePrefix := prefix
			if isLastInterface {
				nodePrefix += "    "
			} else {
				nodePrefix += "│   "
			}

			node := n.nodes[nodeID]
			childPort := node.LocalPort
			if childPort == "" {
				childPort = "??"
			}

			log.Printf("%s%s %s on %s", nodePrefix, nodeConnector, childPort, node)

			grandchildren := n.getChildren(nodeID)
			if len(grandchildren) > 0 {
				grandchildPrefix := nodePrefix
				if isLastNode {
					grandchildPrefix += "    "
				} else {
					grandchildPrefix += "│   "
				}
				n.logChildrenByInterface(nodeID, grandchildPrefix)
			}
		}
	}
}

func (n *Nodes) getChildren(parentID int) []int {
	var children []int
	for id, node := range n.nodes {
		if node.ParentID == parentID && id != 0 {
			children = append(children, id)
		}
	}
	sort.Ints(children)
	return children
}
