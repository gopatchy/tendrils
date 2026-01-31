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
	mu        sync.RWMutex
	nodes     []*Node
	ipIndex   map[string]*Node
	macIndex  map[string]*Node
	nameIndex map[string]*Node
	t         *Tendrils
	ctx       context.Context
	cancelAll context.CancelFunc
}

func NewNodes(t *Tendrils) *Nodes {
	ctx, cancel := context.WithCancel(context.Background())
	return &Nodes{
		ipIndex:   map[string]*Node{},
		macIndex:  map[string]*Node{},
		nameIndex: map[string]*Node{},
		t:         t,
		ctx:       ctx,
		cancelAll: cancel,
	}
}

func (n *Nodes) Shutdown() {
	n.cancelAll()
}

func (n *Nodes) Update(target *Node, mac net.HardwareAddr, ips []net.IP, ifaceName, nodeName, source string) *Node {
	node, changed := n.updateLocked(target, mac, ips, ifaceName, nodeName, source)
	if changed {
		n.t.NotifyUpdate()
	}
	return node
}

func (n *Nodes) updateLocked(target *Node, mac net.HardwareAddr, ips []net.IP, ifaceName, nodeName, source string) (*Node, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if mac == nil && target == nil && len(ips) == 0 && nodeName == "" {
		return nil, false
	}

	node, isNew := n.resolveTargetNode(target, mac, ips, nodeName)

	added := n.applyNodeUpdates(node, mac, ips, ifaceName, nodeName)

	n.logUpdates(node, added, isNew, source)

	if hasNewIP(added) {
		n.triggerPoll(node)
	}

	return node, isNew || len(added) > 0
}

func (n *Nodes) resolveTargetNode(target *Node, mac net.HardwareAddr, ips []net.IP, nodeName string) (*Node, bool) {
	node := n.findOrMergeByMAC(target, mac)
	if node == nil {
		node = n.findByIPs(ips)
	}
	node = n.findOrMergeByName(node, nodeName)

	if node == nil {
		return n.createNode(), true
	}
	return node, false
}

func (n *Nodes) findOrMergeByMAC(target *Node, mac net.HardwareAddr) *Node {
	if mac == nil {
		return target
	}
	macKey := mac.String()
	found := n.macIndex[macKey]
	if found == nil {
		return target
	}
	if target == nil {
		return found
	}
	if found != target {
		n.mergeNodes(target, found)
	}
	return target
}

func (n *Nodes) findByIPs(ips []net.IP) *Node {
	for _, ip := range ips {
		if node := n.ipIndex[ip.String()]; node != nil {
			return node
		}
	}
	return nil
}

func (n *Nodes) findOrMergeByName(target *Node, nodeName string) *Node {
	if nodeName == "" {
		return target
	}
	found := n.nameIndex[nodeName]
	if found == nil {
		return target
	}
	if target == nil {
		return found
	}
	if found != target {
		n.mergeNodes(target, found)
	}
	return target
}

func (n *Nodes) createNode() *Node {
	node := &Node{
		ID:          newID("node"),
		Interfaces:  InterfaceMap{},
		MACTable:    map[string]string{},
		errors:      n.t.errors,
		pollTrigger: make(chan struct{}, 1),
	}
	n.nodes = append(n.nodes, node)
	n.startNodePoller(node)
	return node
}

func (n *Nodes) applyNodeUpdates(node *Node, mac net.HardwareAddr, ips []net.IP, ifaceName, nodeName string) []string {
	var added []string

	if mac != nil {
		added = n.updateNodeInterface(node, mac, ips, ifaceName)
	} else {
		added = n.updateNodeIPs(node, ips)
	}

	if nodeName != "" {
		if node.Names == nil {
			node.Names = NameSet{}
		}
		if !node.Names.Has(nodeName) {
			node.Names.Add(nodeName)
			n.nameIndex[nodeName] = node
			added = append(added, "name="+nodeName)
		}
	}

	return added
}

func (n *Nodes) updateNodeIPs(node *Node, ips []net.IP) []string {
	var added []string
	for _, ip := range ips {
		ipKey := ip.String()
		if existing := n.ipIndex[ipKey]; existing != nil && existing != node {
			n.mergeNodes(node, existing)
			if n.t.LogEvents {
				log.Printf("[merge] %s into %s (shared ip %s)", existing, node, ipKey)
			}
		}
		n.ipIndex[ipKey] = node

		var targetIface *Interface
		for _, iface := range node.Interfaces {
			if iface.MAC != "" {
				targetIface = iface
				break
			}
		}
		if targetIface != nil {
			if !targetIface.IPs.Has(ipKey) {
				targetIface.IPs.Add(ip)
				added = append(added, "ip="+ipKey)
			}
		} else {
			iface, exists := node.Interfaces[ipKey]
			if !exists {
				iface = &Interface{IPs: IPSet{}}
				node.Interfaces[ipKey] = iface
			}
			iface.IPs.Add(ip)
			added = append(added, "ip="+ipKey)
		}
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

func (n *Nodes) startNodePoller(node *Node) {
	ctx, cancel := context.WithCancel(n.ctx)
	node.cancelFunc = cancel

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

func (n *Nodes) updateNodeInterface(node *Node, mac net.HardwareAddr, ips []net.IP, ifaceName string) []string {
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

	if n.macIndex[macKey] == nil {
		n.macIndex[macKey] = node
	}

	for _, ip := range ips {
		ipKey := ip.String()
		if existing := n.ipIndex[ipKey]; existing != nil && existing != node {
			n.mergeNodes(node, existing)
			if n.t.LogEvents {
				log.Printf("[merge] %s into %s (shared ip %s)", existing, node, ipKey)
			}
		}
		if !iface.IPs.Has(ipKey) {
			added = append(added, "ip="+ipKey)
		}
		iface.IPs.Add(ip)
		n.ipIndex[ipKey] = node

		for key, other := range node.Interfaces {
			if other != iface && other.IPs.Has(ipKey) {
				delete(other.IPs, ipKey)
				if len(other.IPs) == 0 && other.MAC == "" {
					delete(node.Interfaces, key)
				}
			}
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

	existing := map[*Node]bool{}
	for _, mac := range macs {
		if node := n.macIndex[mac.String()]; node != nil {
			existing[node] = true
		}
	}

	if len(existing) < 2 {
		return
	}

	var nodes []*Node
	for node := range existing {
		nodes = append(nodes, node)
	}

	target := nodes[0]
	for i := 1; i < len(nodes); i++ {
		if n.t.LogEvents {
			log.Printf("[merge] %s into %s (via %s)", nodes[i], target, source)
		}
		n.mergeNodes(target, nodes[i])
	}

	if n.t.LogNodes {
		n.logNode(target)
	}
}

func (n *Nodes) mergeNodes(keep, merge *Node) {
	if keep == nil || merge == nil || keep == merge {
		return
	}

	for name := range merge.Names {
		if keep.Names == nil {
			keep.Names = NameSet{}
		}
		keep.Names.Add(name)
		n.nameIndex[name] = keep
	}

	for ifaceKey, iface := range merge.Interfaces {
		if iface.MAC != "" {
			n.macIndex[string(iface.MAC)] = keep
		}
		for ipStr := range iface.IPs {
			n.ipIndex[ipStr] = keep
		}
		if _, exists := keep.Interfaces[ifaceKey]; !exists {
			keep.Interfaces[ifaceKey] = iface
		} else {
			keepIface := keep.Interfaces[ifaceKey]
			for ipStr := range iface.IPs {
				keepIface.IPs.Add(net.ParseIP(ipStr))
			}
		}
	}

	for peerMAC, ifaceName := range merge.MACTable {
		if keep.MACTable == nil {
			keep.MACTable = map[string]string{}
		}
		keep.MACTable[peerMAC] = ifaceName
	}

	n.mergeArtNet(keep, merge)
	n.mergeSACN(keep, merge)
	n.mergeMulticast(keep, merge)
	n.mergeDante(keep, merge)

	if merge.cancelFunc != nil {
		merge.cancelFunc()
	}

	n.removeNode(merge)
}

func (n *Nodes) removeNode(node *Node) {
	for i, nd := range n.nodes {
		if nd == node {
			n.nodes = append(n.nodes[:i], n.nodes[i+1:]...)
			return
		}
	}
}

func (n *Nodes) GetByIP(ip net.IP) *Node {
	n.mu.RLock()
	defer n.mu.RUnlock()

	return n.getByIPLocked(ip)
}

func (n *Nodes) getByIPLocked(ip net.IP) *Node {
	return n.ipIndex[ip.String()]
}

func (n *Nodes) GetByMAC(mac net.HardwareAddr) *Node {
	n.mu.RLock()
	defer n.mu.RUnlock()

	return n.macIndex[mac.String()]
}

func (n *Nodes) GetByName(name string) *Node {
	n.mu.RLock()
	defer n.mu.RUnlock()

	return n.nameIndex[name]
}

func (n *Nodes) GetOrCreateByName(name string) *Node {
	n.mu.Lock()
	defer n.mu.Unlock()

	if node := n.nameIndex[name]; node != nil {
		return node
	}

	node := &Node{
		ID:          newID("node"),
		Names:       NameSet{name: true},
		Interfaces:  InterfaceMap{},
		MACTable:    map[string]string{},
		errors:      n.t.errors,
		pollTrigger: make(chan struct{}, 1),
	}
	n.nodes = append(n.nodes, node)
	n.nameIndex[name] = node
	n.startNodePoller(node)

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

	if node := n.ipIndex[ip.String()]; node != nil {
		node.DanteClockMasterSeen = time.Now()
	}
}

func (n *Nodes) getNodeByIPLocked(ip net.IP) *Node {
	return n.ipIndex[ip.String()]
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
	if node.IsDanteClockMaster() {
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

	groupMembers := map[string][]string{}
	for _, node := range n.nodes {
		if node.MulticastGroups == nil {
			continue
		}
		for _, group := range node.MulticastGroups.Groups() {
			name := node.DisplayName()
			if name == "" {
				name = "??"
			}
			groupMembers[group.String()] = append(groupMembers[group.String()], name)
		}
	}

	if len(groupMembers) > 0 {
		var groupNames []string
		for name := range groupMembers {
			groupNames = append(groupNames, name)
		}
		sort.Slice(groupNames, func(i, j int) bool {
			return sortorder.NaturalLess(groupNames[i], groupNames[j])
		})

		log.Printf("[sigusr1] ================ %d multicast groups ================", len(groupNames))
		for _, groupName := range groupNames {
			members := groupMembers[groupName]
			sort.Slice(members, func(i, j int) bool {
				return sortorder.NaturalLess(members[i], members[j])
			})
			log.Printf("[sigusr1]   %s: %s", groupName, strings.Join(members, ", "))
		}
	}

	n.logArtNet()
	n.logDante()
}

func (n *Nodes) ApplyConfig(cfg *Config) {
	if cfg == nil {
		return
	}
	for _, nc := range cfg.AllNodeConfigs() {
		n.applyNodeConfig(nc)
	}
}

func (n *Nodes) applyNodeConfig(nc *NodeConfig) {
	if len(nc.Names) == 0 && len(nc.MACs) == 0 && len(nc.IPs) == 0 {
		return
	}

	var macs []net.HardwareAddr
	for _, macStr := range nc.MACs {
		if mac, err := net.ParseMAC(macStr); err == nil {
			macs = append(macs, mac)
		}
	}

	var ips []net.IP
	for _, ipStr := range nc.IPs {
		if ip := net.ParseIP(ipStr); ip != nil {
			ips = append(ips, ip)
		}
	}

	var firstMAC net.HardwareAddr
	if len(macs) > 0 {
		firstMAC = macs[0]
	}
	firstName := ""
	if len(nc.Names) > 0 {
		firstName = nc.Names[0]
	}

	target := n.Update(nil, firstMAC, ips, "", firstName, "config")
	if target == nil {
		return
	}

	for i := 1; i < len(macs); i++ {
		n.Update(target, macs[i], nil, "", "", "config")
	}
	for i := 1; i < len(nc.Names); i++ {
		n.Update(target, nil, nil, "", nc.Names[i], "config")
	}

	if nc.Avoid {
		n.setAvoid(target)
	}
}

func (n *Nodes) setAvoid(node *Node) {
	n.mu.Lock()
	defer n.mu.Unlock()
	node.Avoid = true
}
