package tendrils

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fvbommel/sortorder"
)

type Nodes struct {
	mu              sync.RWMutex
	nodes           map[int]*Node
	ipIndex         map[string]int
	macIndex        map[string]int
	nameIndex       map[string]int
	nodeCancel      map[int]context.CancelFunc
	multicastGroups map[string]*MulticastGroupMembers
	nextID          int
	t               *Tendrils
	ctx             context.Context
	cancelAll       context.CancelFunc
}

func NewNodes(t *Tendrils) *Nodes {
	ctx, cancel := context.WithCancel(context.Background())
	return &Nodes{
		nodes:           map[int]*Node{},
		ipIndex:         map[string]int{},
		macIndex:        map[string]int{},
		nameIndex:       map[string]int{},
		nodeCancel:      map[int]context.CancelFunc{},
		multicastGroups: map[string]*MulticastGroupMembers{},
		nextID:          1,
		t:               t,
		ctx:             ctx,
		cancelAll:       cancel,
	}
}

func (n *Nodes) Shutdown() {
	n.cancelAll()
}

func (n *Nodes) Update(target *Node, mac net.HardwareAddr, ips []net.IP, ifaceName, nodeName, source string) {
	changed := n.updateLocked(target, mac, ips, ifaceName, nodeName, source)
	if changed {
		n.t.NotifyUpdate()
	}
}

func (n *Nodes) updateLocked(target *Node, mac net.HardwareAddr, ips []net.IP, ifaceName, nodeName, source string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	if mac == nil && target == nil && len(ips) == 0 {
		return false
	}

	targetID, isNew := n.resolveTargetNode(target, mac, ips, nodeName)
	node := n.nodes[targetID]

	added := n.applyNodeUpdates(node, targetID, mac, ips, ifaceName, nodeName)

	n.logUpdates(node, added, isNew, source)

	if hasNewIP(added) {
		n.triggerPoll(node)
	}

	return isNew || len(added) > 0
}

func (n *Nodes) resolveTargetNode(target *Node, mac net.HardwareAddr, ips []net.IP, nodeName string) (int, bool) {
	targetID := n.findByTarget(target)
	targetID = n.findOrMergeByMAC(targetID, mac)
	if targetID == -1 {
		targetID = n.findByIPs(ips)
	}
	targetID = n.findOrMergeByName(targetID, nodeName)

	if targetID == -1 {
		return n.createNode(), true
	}
	return targetID, false
}

func (n *Nodes) findByTarget(target *Node) int {
	if target == nil {
		return -1
	}
	for id, node := range n.nodes {
		if node == target {
			return id
		}
	}
	return -1
}

func (n *Nodes) findOrMergeByMAC(targetID int, mac net.HardwareAddr) int {
	if mac == nil {
		return targetID
	}
	macKey := mac.String()
	id, exists := n.macIndex[macKey]
	if !exists {
		return targetID
	}
	if _, nodeExists := n.nodes[id]; !nodeExists {
		delete(n.macIndex, macKey)
		return targetID
	}
	if targetID == -1 {
		return id
	}
	if id != targetID {
		n.mergeNodes(targetID, id)
	}
	return targetID
}

func (n *Nodes) findByIPs(ips []net.IP) int {
	for _, ip := range ips {
		if id, exists := n.ipIndex[ip.String()]; exists {
			if _, nodeExists := n.nodes[id]; nodeExists {
				return id
			}
		}
	}
	return -1
}

func (n *Nodes) findOrMergeByName(targetID int, nodeName string) int {
	if nodeName == "" {
		return targetID
	}
	id, exists := n.nameIndex[nodeName]
	if !exists {
		return targetID
	}
	nameNode, nodeExists := n.nodes[id]
	if !nodeExists {
		delete(n.nameIndex, nodeName)
		return targetID
	}
	if targetID == -1 {
		return id
	}
	if id != targetID && len(nameNode.Interfaces) == 0 {
		n.mergeNodes(targetID, id)
	}
	return targetID
}

func (n *Nodes) createNode() int {
	targetID := n.nextID
	n.nextID++
	node := &Node{
		TypeID:      newTypeID("node"),
		Interfaces:  InterfaceMap{},
		MACTable:    map[string]string{},
		pollTrigger: make(chan struct{}, 1),
	}
	n.nodes[targetID] = node
	n.startNodePoller(targetID, node)
	return targetID
}

func (n *Nodes) applyNodeUpdates(node *Node, nodeID int, mac net.HardwareAddr, ips []net.IP, ifaceName, nodeName string) []string {
	var added []string

	if mac != nil {
		added = n.updateNodeInterface(node, nodeID, mac, ips, ifaceName)
	} else {
		added = n.updateNodeIPs(node, nodeID, ips)
	}

	if nodeName != "" {
		if node.Names == nil {
			node.Names = NameSet{}
		}
		if !node.Names.Has(nodeName) {
			node.Names.Add(nodeName)
			n.nameIndex[nodeName] = nodeID
			added = append(added, "name="+nodeName)
		}
	}

	return added
}

func (n *Nodes) updateNodeIPs(node *Node, nodeID int, ips []net.IP) []string {
	var added []string
	for _, ip := range ips {
		ipKey := ip.String()
		if existingID, exists := n.ipIndex[ipKey]; exists {
			if existingID == nodeID {
				continue
			}
			if existingNode, nodeExists := n.nodes[existingID]; nodeExists {
				n.mergeNodes(nodeID, existingID)
				if n.t.LogEvents {
					log.Printf("[merge] %s into %s (shared ip %s)", existingNode, node, ipKey)
				}
			}
		}
		n.ipIndex[ipKey] = nodeID
		iface, exists := node.Interfaces[ipKey]
		if !exists {
			iface = &Interface{IPs: IPSet{}}
			node.Interfaces[ipKey] = iface
		}
		iface.IPs.Add(ip)
		added = append(added, "ip="+ipKey)
		go n.t.requestARP(ip)
	}
	return added
}

func hasNewIP(added []string) bool {
	for _, a := range added {
		if len(a) > 3 && a[:3] == "ip=" {
			return true
		}
	}
	return false
}

func (n *Nodes) logUpdates(node *Node, added []string, isNew bool, source string) {
	if len(added) == 0 {
		return
	}
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

func (n *Nodes) startNodePoller(nodeID int, node *Node) {
	ctx, cancel := context.WithCancel(n.ctx)
	n.nodeCancel[nodeID] = cancel

	go func() {
		pollTicker := time.NewTicker(10 * time.Second)
		pingTicker := time.NewTicker(5 * time.Second)
		defer pollTicker.Stop()
		defer pingTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-node.pollTrigger:
				n.t.pollNode(node)
			case <-pollTicker.C:
				n.t.pollNode(node)
			case <-pingTicker.C:
				n.t.pingNode(node)
			}
		}
	}()
}

func (n *Nodes) triggerPoll(node *Node) {
	select {
	case node.pollTrigger <- struct{}{}:
	default:
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
		iface, exists, added = n.findOrCreateInterface(node, macKey, ifaceName, ifaceKey)
	}
	if !exists {
		iface = &Interface{
			Name: ifaceName,
			MAC:  MACFrom(mac),
			IPs:  IPSet{},
		}
		node.Interfaces[ifaceKey] = iface
		added = append(added, "iface="+ifaceKey)
	}

	if _, exists := n.macIndex[macKey]; !exists {
		n.macIndex[macKey] = nodeID
	}

	for _, ip := range ips {
		ipKey := ip.String()
		if existingID, exists := n.ipIndex[ipKey]; exists && existingID != nodeID {
			if existingNode, nodeExists := n.nodes[existingID]; nodeExists {
				n.mergeNodes(nodeID, existingID)
				if n.t.LogEvents {
					log.Printf("[merge] %s into %s (shared ip %s)", existingNode, node, ipKey)
				}
			}
		}
		if !iface.IPs.Has(ipKey) {
			added = append(added, "ip="+ipKey)
		}
		iface.IPs.Add(ip)
		n.ipIndex[ipKey] = nodeID

		if ipOnlyIface, exists := node.Interfaces[ipKey]; exists && ipOnlyIface != iface {
			delete(node.Interfaces, ipKey)
		}
	}

	return added
}

func (n *Nodes) findOrCreateInterface(node *Node, macKey, ifaceName, ifaceKey string) (*Interface, bool, []string) {
	var added []string

	if ifaceName != "" {
		if oldIface, oldExists := node.Interfaces[macKey]; oldExists && string(oldIface.MAC) == macKey {
			oldIface.Name = ifaceName
			delete(node.Interfaces, macKey)
			node.Interfaces[ifaceKey] = oldIface
			return oldIface, true, append(added, "iface="+ifaceKey)
		}
	} else {
		for _, existing := range node.Interfaces {
			if string(existing.MAC) == macKey {
				return existing, true, added
			}
		}
	}
	return nil, false, added
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

	for name := range merge.Names {
		if keep.Names == nil {
			keep.Names = NameSet{}
		}
		keep.Names.Add(name)
		n.nameIndex[name] = keepID
	}

	for _, iface := range merge.Interfaces {
		var ips []net.IP
		for ipStr := range iface.IPs {
			ips = append(ips, net.ParseIP(ipStr))
		}
		if iface.MAC != "" {
			n.updateNodeInterface(keep, keepID, iface.MAC.Parse(), ips, iface.Name)
			n.macIndex[string(iface.MAC)] = keepID
		}
	}

	for peerMAC, ifaceName := range merge.MACTable {
		if keep.MACTable == nil {
			keep.MACTable = map[string]string{}
		}
		keep.MACTable[peerMAC] = ifaceName
	}

	n.t.danteFlows.ReplaceNode(merge, keep)
	n.t.artnet.ReplaceNode(merge, keep)

	for _, gm := range n.multicastGroups {
		for _, membership := range gm.Members {
			if membership.Node == merge {
				membership.Node = keep
			}
		}
	}

	if cancel, exists := n.nodeCancel[mergeID]; exists {
		cancel()
		delete(n.nodeCancel, mergeID)
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

func (n *Nodes) GetByName(name string) *Node {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if id, exists := n.nameIndex[name]; exists {
		return n.nodes[id]
	}
	return nil
}

func (n *Nodes) GetOrCreateByName(name string) *Node {
	n.mu.Lock()
	defer n.mu.Unlock()

	if id, exists := n.nameIndex[name]; exists {
		if node, nodeExists := n.nodes[id]; nodeExists {
			return node
		}
		delete(n.nameIndex, name)
	}

	targetID := n.nextID
	n.nextID++
	node := &Node{
		TypeID:      newTypeID("node"),
		Names:       NameSet{name: true},
		Interfaces:  InterfaceMap{},
		MACTable:    map[string]string{},
		pollTrigger: make(chan struct{}, 1),
	}
	n.nodes[targetID] = node
	n.nameIndex[name] = targetID
	n.startNodePoller(targetID, node)

	if n.t.LogEvents {
		log.Printf("[add] %s [name=%s] (via name-lookup)", node, name)
	}

	return node
}

func (n *Nodes) UpdateMACTable(node *Node, peerMAC net.HardwareAddr, ifaceName string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if node.MACTable == nil {
		node.MACTable = map[string]string{}
	}
	node.MACTable[peerMAC.String()] = ifaceName
}

func (n *Nodes) SetDanteClockMaster(ip net.IP) {
	n.Update(nil, nil, []net.IP{ip}, "", "", "ptp")

	n.mu.Lock()
	defer n.mu.Unlock()

	for _, node := range n.nodes {
		node.IsDanteClockMaster = false
	}

	if id, exists := n.ipIndex[ip.String()]; exists {
		n.nodes[id].IsDanteClockMaster = true
	}
}

func (n *Nodes) getNodeByIPLocked(ip net.IP) *Node {
	if id, exists := n.ipIndex[ip.String()]; exists {
		return n.nodes[id]
	}
	return nil
}

func (n *Nodes) logNode(node *Node) {
	name := node.DisplayName()
	if name == "" {
		name = "??"
	}
	var tags []string
	if node.PoEBudget != nil {
		tags = append(tags, fmt.Sprintf("poe:%.0f/%.0fW", node.PoEBudget.Power, node.PoEBudget.MaxPower))
	}
	if node.IsDanteClockMaster {
		tags = append(tags, "dante-clock-master")
	}
	if len(tags) > 0 {
		log.Printf("[node] %s [%s]", name, strings.Join(tags, " "))
	} else {
		log.Printf("[node] %s", name)
	}

	var ifaceKeys []string
	for ifaceKey := range node.Interfaces {
		ifaceKeys = append(ifaceKeys, ifaceKey)
	}
	sort.Slice(ifaceKeys, func(i, j int) bool { return sortorder.NaturalLess(ifaceKeys[i], ifaceKeys[j]) })

	for _, ifaceKey := range ifaceKeys {
		iface := node.Interfaces[ifaceKey]
		log.Printf("[node]   %s", iface)
	}

	if len(node.MACTable) > 0 {
		log.Printf("[node]   mac table: %d entries", len(node.MACTable))
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

func (n *Nodes) LogAll() {
	n.mu.RLock()
	defer n.mu.RUnlock()

	nodes := make([]*Node, 0, len(n.nodes))
	for _, node := range n.nodes {
		nodes = append(nodes, node)
	}
	sort.Slice(nodes, func(i, j int) bool {
		return sortorder.NaturalLess(nodes[i].DisplayName(), nodes[j].DisplayName())
	})

	log.Printf("[sigusr1] ================ %d nodes ================", len(nodes))
	for _, node := range nodes {
		n.logNode(node)
	}

	links := n.getDirectLinks()
	sort.Slice(links, func(i, j int) bool {
		if links[i].NodeA.DisplayName() != links[j].NodeA.DisplayName() {
			return sortorder.NaturalLess(links[i].NodeA.DisplayName(), links[j].NodeA.DisplayName())
		}
		if links[i].InterfaceA != links[j].InterfaceA {
			return sortorder.NaturalLess(links[i].InterfaceA, links[j].InterfaceA)
		}
		if links[i].NodeB.DisplayName() != links[j].NodeB.DisplayName() {
			return sortorder.NaturalLess(links[i].NodeB.DisplayName(), links[j].NodeB.DisplayName())
		}
		if links[i].InterfaceB != links[j].InterfaceB {
			return sortorder.NaturalLess(links[i].InterfaceB, links[j].InterfaceB)
		}
		return false
	})

	if len(links) > 0 {
		log.Printf("[sigusr1] ================ %d links ================", len(links))
		for _, link := range links {
			log.Printf("[sigusr1]   %s", link)
		}
	}

	n.expireMulticastMemberships()

	if len(n.multicastGroups) > 0 {
		var groups []*MulticastGroupMembers
		for _, gm := range n.multicastGroups {
			groups = append(groups, gm)
		}
		sort.Slice(groups, func(i, j int) bool {
			return sortorder.NaturalLess(groups[i].Group.Name, groups[j].Group.Name)
		})

		log.Printf("[sigusr1] ================ %d multicast groups ================", len(groups))
		for _, gm := range groups {
			var memberNames []string
			for sourceIP, membership := range gm.Members {
				var name string
				if membership.Node != nil {
					name = membership.Node.DisplayName()
					if name == "" {
						name = sourceIP
					}
				} else {
					name = sourceIP
				}
				memberNames = append(memberNames, name)
			}
			sort.Slice(memberNames, func(i, j int) bool {
				return sortorder.NaturalLess(memberNames[i], memberNames[j])
			})
			log.Printf("[sigusr1]   %s: %s", gm.Group.Name, strings.Join(memberNames, ", "))
		}
	}

	n.t.artnet.LogAll()
	n.t.danteFlows.LogAll()
}
