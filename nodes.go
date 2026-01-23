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

type Interface struct {
	Name  string
	MAC   net.HardwareAddr
	IPs   map[string]net.IP
	Stats *InterfaceStats
}

type InterfaceStats struct {
	Speed     uint64 // bits per second
	InErrors  uint64
	OutErrors uint64
	PoE       *PoEStats
}

type PoEStats struct {
	Power    float64 // watts in use
	MaxPower float64 // watts allocated/negotiated
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
	if i.Stats != nil {
		parts = append(parts, i.Stats.String())
	}

	result := parts[0]
	for _, p := range parts[1:] {
		result += " " + p
	}
	return result
}

func (s *InterfaceStats) String() string {
	var parts []string

	if s.Speed > 0 {
		if s.Speed >= 1000000000 {
			parts = append(parts, fmt.Sprintf("%dG", s.Speed/1000000000))
		} else if s.Speed >= 1000000 {
			parts = append(parts, fmt.Sprintf("%dM", s.Speed/1000000))
		} else {
			parts = append(parts, fmt.Sprintf("%d", s.Speed))
		}
	}

	if s.InErrors > 0 || s.OutErrors > 0 {
		parts = append(parts, fmt.Sprintf("err:%d/%d", s.InErrors, s.OutErrors))
	}

	if s.PoE != nil {
		if s.PoE.MaxPower > 0 {
			parts = append(parts, fmt.Sprintf("poe:%.1f/%.1fW", s.PoE.Power, s.PoE.MaxPower))
		} else {
			parts = append(parts, fmt.Sprintf("poe:%.1fW", s.PoE.Power))
		}
	}

	return "[" + fmt.Sprintf("%s", joinParts(parts)) + "]"
}

func joinParts(parts []string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += " "
		}
		result += p
	}
	return result
}

type PoEBudget struct {
	Power    float64 // watts in use
	MaxPower float64 // watts total budget
}

type Node struct {
	Name               string
	Interfaces         map[string]*Interface
	MACTable           map[string]string // peer MAC -> local interface name
	PoEBudget          *PoEBudget
	IsDanteClockMaster bool
	pollTrigger        chan struct{}
}

func (n *Node) String() string {
	name := n.Name
	if name == "" {
		name = "??"
	}

	var parts []string
	parts = append(parts, name)

	if n.PoEBudget != nil {
		parts = append(parts, fmt.Sprintf("[poe:%.0f/%.0fW]", n.PoEBudget.Power, n.PoEBudget.MaxPower))
	}

	var ifaces []string
	for _, iface := range n.Interfaces {
		ifaces = append(ifaces, iface.String())
	}
	sort.Slice(ifaces, func(i, j int) bool { return sortorder.NaturalLess(ifaces[i], ifaces[j]) })

	parts = append(parts, fmt.Sprintf("{%v}", ifaces))

	return joinParts(parts)
}

type MulticastGroup struct {
	IP net.IP
}

func (g *MulticastGroup) Name() string {
	ip := g.IP.To4()
	if ip == nil {
		return g.IP.String()
	}

	// Well-known multicast addresses
	switch g.IP.String() {
	case "224.0.0.251":
		return "mdns"
	case "224.0.1.129":
		return "ptp"
	case "224.0.1.130":
		return "ptp-announce"
	case "224.0.1.131":
		return "ptp-sync"
	case "224.0.1.132":
		return "ptp-delay"
	case "224.2.127.254":
		return "sap"
	case "239.255.254.253":
		return "shure-slp"
	case "239.255.255.250":
		return "ssdp"
	case "239.255.255.253":
		return "slp"
	case "239.255.255.255":
		return "admin-scoped-broadcast"
	}

	// sACN (239.255.x.x, universes 1-63999)
	if ip[0] == 239 && ip[1] == 255 {
		universe := int(ip[2])*256 + int(ip[3])
		if universe >= 1 && universe <= 63999 {
			return fmt.Sprintf("sacn:%d", universe)
		}
	}

	// Dante audio multicast (239.69-71.x.x)
	if ip[0] == 239 && ip[1] >= 69 && ip[1] <= 71 {
		flowID := (int(ip[1]-69) << 16) | (int(ip[2]) << 8) | int(ip[3])
		return fmt.Sprintf("dante-mcast:%d", flowID)
	}

	// Dante AV multicast (239.253.x.x)
	if ip[0] == 239 && ip[1] == 253 {
		flowID := (int(ip[2]) << 8) | int(ip[3])
		return fmt.Sprintf("dante-av:%d", flowID)
	}

	return g.IP.String()
}

func (g *MulticastGroup) IsDante() bool {
	ip := g.IP.To4()
	if ip == nil {
		return false
	}
	if ip[0] == 239 && ip[1] >= 69 && ip[1] <= 71 {
		return true
	}
	if ip[0] == 239 && ip[1] == 253 {
		return true
	}
	return false
}

type MulticastMembership struct {
	Node     *Node
	LastSeen time.Time
}

type MulticastGroupMembers struct {
	Group   *MulticastGroup
	Members map[string]*MulticastMembership // source IP -> membership
}

type Nodes struct {
	mu              sync.RWMutex
	nodes           map[int]*Node
	ipIndex         map[string]int
	macIndex        map[string]int
	nodeCancel      map[int]context.CancelFunc
	multicastGroups map[string]*MulticastGroupMembers // group IP string -> group with members
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
	n.mu.Lock()
	defer n.mu.Unlock()

	if mac == nil && target == nil && len(ips) == 0 {
		return
	}

	targetID := -1
	isNew := false

	if target != nil {
		for id, node := range n.nodes {
			if node == target {
				targetID = id
				break
			}
		}
	}

	if mac != nil {
		macKey := mac.String()
		if id, exists := n.macIndex[macKey]; exists {
			if _, nodeExists := n.nodes[id]; nodeExists {
				if targetID == -1 {
					targetID = id
				} else if id != targetID {
					n.mergeNodes(targetID, id)
				}
			} else {
				delete(n.macIndex, macKey)
			}
		}
	}

	if targetID == -1 {
		for _, ip := range ips {
			if id, exists := n.ipIndex[ip.String()]; exists {
				if _, nodeExists := n.nodes[id]; nodeExists {
					targetID = id
					break
				}
			}
		}
	}

	var node *Node
	if targetID == -1 {
		targetID = n.nextID
		n.nextID++
		node = &Node{
			Interfaces:  map[string]*Interface{},
			MACTable:    map[string]string{},
			pollTrigger: make(chan struct{}, 1),
		}
		n.nodes[targetID] = node
		isNew = true
		n.startNodePoller(targetID, node)
	} else {
		node = n.nodes[targetID]
	}

	var added []string
	if mac != nil {
		added = n.updateNodeInterface(node, targetID, mac, ips, ifaceName)
	} else {
		for _, ip := range ips {
			ipKey := ip.String()
			if _, exists := n.ipIndex[ipKey]; !exists {
				n.ipIndex[ipKey] = targetID
				iface, exists := node.Interfaces[ipKey]
				if !exists {
					iface = &Interface{
						IPs: map[string]net.IP{},
					}
					node.Interfaces[ipKey] = iface
				}
				iface.IPs[ipKey] = ip
				added = append(added, "ip="+ipKey)
				go n.t.requestARP(ip)
			}
		}
	}

	if nodeName != "" && node.Name == "" {
		node.Name = nodeName
		added = append(added, "name="+nodeName)
	}

	hasNewIP := false
	for _, a := range added {
		if len(a) > 3 && a[:3] == "ip=" {
			hasNewIP = true
			break
		}
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

	if hasNewIP {
		n.triggerPoll(node)
	}
}

func (n *Nodes) startNodePoller(nodeID int, node *Node) {
	ctx, cancel := context.WithCancel(n.ctx)
	n.nodeCancel[nodeID] = cancel

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-node.pollTrigger:
				n.t.pollNode(node)
			case <-ticker.C:
				n.t.pollNode(node)
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

	for peerMAC, ifaceName := range merge.MACTable {
		if keep.MACTable == nil {
			keep.MACTable = map[string]string{}
		}
		keep.MACTable[peerMAC] = ifaceName
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


func (n *Nodes) UpdateMACTable(node *Node, peerMAC net.HardwareAddr, ifaceName string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if node.MACTable == nil {
		node.MACTable = map[string]string{}
	}
	node.MACTable[peerMAC.String()] = ifaceName
}

func (n *Nodes) SetDanteClockMaster(ip net.IP) {
	n.mu.RLock()
	currentMaster := ""
	for _, node := range n.nodes {
		if node.IsDanteClockMaster {
			currentMaster = ip.String()
			break
		}
	}
	n.mu.RUnlock()

	if currentMaster != ip.String() {
		n.Update(nil, nil, []net.IP{ip}, "", "", "ptp")
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	for _, node := range n.nodes {
		node.IsDanteClockMaster = false
	}

	if id, exists := n.ipIndex[ip.String()]; exists {
		n.nodes[id].IsDanteClockMaster = true
	}
}

func (n *Nodes) UpdateMulticastMembership(sourceIP, groupIP net.IP) {
	n.mu.Lock()
	defer n.mu.Unlock()

	node := n.getNodeByIPLocked(sourceIP)

	groupKey := groupIP.String()
	sourceKey := sourceIP.String()

	gm := n.multicastGroups[groupKey]
	if gm == nil {
		gm = &MulticastGroupMembers{
			Group:   &MulticastGroup{IP: groupIP},
			Members: map[string]*MulticastMembership{},
		}
		n.multicastGroups[groupKey] = gm
	}

	gm.Members[sourceKey] = &MulticastMembership{
		Node:     node,
		LastSeen: time.Now(),
	}
}

func (n *Nodes) RemoveMulticastMembership(sourceIP, groupIP net.IP) {
	n.mu.Lock()
	defer n.mu.Unlock()

	groupKey := groupIP.String()
	sourceKey := sourceIP.String()

	if gm := n.multicastGroups[groupKey]; gm != nil {
		delete(gm.Members, sourceKey)
		if len(gm.Members) == 0 {
			delete(n.multicastGroups, groupKey)
		}
	}
}

func (n *Nodes) getNodeByIPLocked(ip net.IP) *Node {
	if id, exists := n.ipIndex[ip.String()]; exists {
		return n.nodes[id]
	}
	return nil
}

func (n *Nodes) GetDanteMulticastGroups(deviceIP net.IP) []net.IP {
	n.mu.RLock()
	defer n.mu.RUnlock()

	deviceKey := deviceIP.String()
	var groups []net.IP

	for _, gm := range n.multicastGroups {
		if !gm.Group.IsDante() {
			continue
		}
		if _, exists := gm.Members[deviceKey]; exists {
			groups = append(groups, gm.Group.IP)
		}
	}
	return groups
	return nil
}

func (n *Nodes) logNode(node *Node) {
	name := node.Name
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
		log.Printf("[node] %s [%s]", name, joinParts(tags))
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
		return sortorder.NaturalLess(nodes[i].Name, nodes[j].Name)
	})

	log.Printf("[sigusr1] ================ %d nodes ================", len(nodes))
	for _, node := range nodes {
		n.logNode(node)
	}

	links := n.getDirectLinks()
	sort.Slice(links, func(i, j int) bool {
		if links[i].NodeA.Name != links[j].NodeA.Name {
			return sortorder.NaturalLess(links[i].NodeA.Name, links[j].NodeA.Name)
		}
		if links[i].InterfaceA != links[j].InterfaceA {
			return sortorder.NaturalLess(links[i].InterfaceA, links[j].InterfaceA)
		}
		if links[i].NodeB.Name != links[j].NodeB.Name {
			return sortorder.NaturalLess(links[i].NodeB.Name, links[j].NodeB.Name)
		}
		return sortorder.NaturalLess(links[i].InterfaceB, links[j].InterfaceB)
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
			return sortorder.NaturalLess(groups[i].Group.Name(), groups[j].Group.Name())
		})

		log.Printf("[sigusr1] ================ %d multicast groups ================", len(groups))
		for _, gm := range groups {
			var memberNames []string
			for sourceIP, membership := range gm.Members {
				var name string
				if membership.Node != nil {
					name = membership.Node.Name
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
			log.Printf("[sigusr1]   %s: %s", gm.Group.Name(), strings.Join(memberNames, ", "))
		}
	}

	n.t.artnet.LogAll()
	n.t.danteFlows.LogAll()
}

func (n *Nodes) expireMulticastMemberships() {
	expireTime := time.Now().Add(-5 * time.Minute)
	for groupKey, gm := range n.multicastGroups {
		for sourceKey, membership := range gm.Members {
			if membership.LastSeen.Before(expireTime) {
				delete(gm.Members, sourceKey)
			}
		}
		if len(gm.Members) == 0 {
			delete(n.multicastGroups, groupKey)
		}
	}
}

type Link struct {
	NodeA      *Node
	InterfaceA string
	NodeB      *Node
	InterfaceB string
}

func (l *Link) String() string {
	nameA := l.NodeA.Name
	if nameA == "" {
		nameA = "??"
	}
	nameB := l.NodeB.Name
	if nameB == "" {
		nameB = "??"
	}
	return fmt.Sprintf("%s:%s <-> %s:%s", nameA, l.InterfaceA, nameB, l.InterfaceB)
}

func (n *Nodes) getDirectLinks() []*Link {
	macToNode := map[string]*Node{}
	for _, node := range n.nodes {
		for _, iface := range node.Interfaces {
			macToNode[iface.MAC.String()] = node
		}
	}

	seen := map[string]bool{}
	var links []*Link

	for _, target := range n.nodes {
		seenMACs := map[string]bool{}
		for _, iface := range target.Interfaces {
			mac := iface.MAC.String()
			if seenMACs[mac] {
				continue
			}
			seenMACs[mac] = true

			var lastHop *Node
			var lastPort string

			for _, node := range n.nodes {
				port, sees := node.MACTable[mac]
				if !sees || node == target {
					continue
				}

				hasCloserNode := false
				for otherMAC, otherPort := range node.MACTable {
					if otherPort != port {
						continue
					}
					otherNode := macToNode[otherMAC]
					if otherNode == nil || otherNode == node || otherNode == target {
						continue
					}
					if _, alsoSees := otherNode.MACTable[mac]; alsoSees {
						hasCloserNode = true
						break
					}
				}

				if !hasCloserNode {
					lastHop = node
					lastPort = port
					break
				}
			}

			if lastHop != nil {
				targetIface := mac
				for lastHopMAC, targetPort := range target.MACTable {
					if macToNode[lastHopMAC] == lastHop {
						targetIface = targetPort
						break
					}
				}

				key := makeLinkKey(lastHop, lastPort, target, targetIface)
				if !seen[key] {
					seen[key] = true
					links = append(links, &Link{
						NodeA:      lastHop,
						InterfaceA: lastPort,
						NodeB:      target,
						InterfaceB: targetIface,
					})
				}
			}
		}
	}

	return links
}

func makeLinkKey(nodeA *Node, ifaceA string, nodeB *Node, ifaceB string) string {
	ptrA := fmt.Sprintf("%p", nodeA)
	ptrB := fmt.Sprintf("%p", nodeB)
	if ptrA < ptrB {
		return ptrA + ":" + ifaceA + "-" + ptrB + ":" + ifaceB
	}
	return ptrB + ":" + ifaceB + "-" + ptrA + ":" + ifaceA
}
