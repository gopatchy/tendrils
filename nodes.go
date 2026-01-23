package tendrils

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
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
	Name        string
	Interfaces  map[string]*Interface
	MACTable    map[string]string // peer MAC -> local interface name
	PoEBudget   *PoEBudget
	pollTrigger chan struct{}
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

type Nodes struct {
	mu          sync.RWMutex
	nodes       map[int]*Node
	ipIndex     map[string]int
	macIndex    map[string]int
	nodeCancel  map[int]context.CancelFunc
	nextID      int
	t           *Tendrils
	ctx         context.Context
	cancelAll   context.CancelFunc
}

func NewNodes(t *Tendrils) *Nodes {
	ctx, cancel := context.WithCancel(context.Background())
	return &Nodes{
		nodes:      map[int]*Node{},
		ipIndex:    map[string]int{},
		macIndex:   map[string]int{},
		nodeCancel: map[int]context.CancelFunc{},
		nextID:     1,
		t:          t,
		ctx:        ctx,
		cancelAll:  cancel,
	}
}

func (n *Nodes) Shutdown() {
	n.cancelAll()
}

func (n *Nodes) Update(target *Node, mac net.HardwareAddr, ips []net.IP, ifaceName, nodeName, source string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if mac == nil && target == nil {
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

func (n *Nodes) logNode(node *Node) {
	name := node.Name
	if name == "" {
		name = "??"
	}
	if node.PoEBudget != nil {
		log.Printf("[node] %s [poe:%.0f/%.0fW]", name, node.PoEBudget.Power, node.PoEBudget.MaxPower)
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

	log.Printf("[sigusr1] ================ %d nodes ================", len(n.nodes))
	for _, node := range n.nodes {
		n.logNode(node)
	}
}
