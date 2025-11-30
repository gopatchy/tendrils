package tendrils

import (
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
)

type Neighbor struct {
	IPs  map[string]net.IP
	MACs map[string]net.HardwareAddr
}

func (n *Neighbor) String() string {
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

type Neighbors struct {
	mu        sync.RWMutex
	neighbors map[int]*Neighbor
	ipIndex   map[string]int
	macIndex  map[string]int
	nextID    int
}

func NewNeighbors() *Neighbors {
	return &Neighbors{
		neighbors: map[int]*Neighbor{},
		ipIndex:   map[string]int{},
		macIndex:  map[string]int{},
		nextID:    1,
	}
}

func (n *Neighbors) Update(ips []net.IP, macs []net.HardwareAddr, source string) {
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
	if len(existingIDs) == 0 {
		targetID = n.nextID
		n.nextID++
		n.neighbors[targetID] = &Neighbor{
			IPs:  map[string]net.IP{},
			MACs: map[string]net.HardwareAddr{},
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
			merging = append(merging, n.neighbors[ids[i]].String())
			n.mergeNeighbors(targetID, ids[i])
		}
		log.Printf("[%s] merged neighbors %v into %s", source, merging, n.neighbors[targetID])
	}

	neighbor := n.neighbors[targetID]
	var added []string

	for _, ip := range ips {
		ipKey := ip.String()
		if _, exists := neighbor.IPs[ipKey]; !exists {
			added = append(added, "ip="+ipKey)
		}
		neighbor.IPs[ipKey] = ip
		n.ipIndex[ipKey] = targetID
	}

	for _, mac := range macs {
		macKey := mac.String()
		if _, exists := neighbor.MACs[macKey]; !exists {
			added = append(added, "mac="+macKey)
		}
		neighbor.MACs[macKey] = mac
		n.macIndex[macKey] = targetID
	}

	if len(added) > 0 {
		log.Printf("[%s] updated %s +%v", source, neighbor, added)
	}
}

func (n *Neighbors) mergeNeighbors(keepID, mergeID int) {
	keep := n.neighbors[keepID]
	merge := n.neighbors[mergeID]

	for ipKey, ip := range merge.IPs {
		keep.IPs[ipKey] = ip
		n.ipIndex[ipKey] = keepID
	}

	for macKey, mac := range merge.MACs {
		keep.MACs[macKey] = mac
		n.macIndex[macKey] = keepID
	}

	delete(n.neighbors, mergeID)
}

func (n *Neighbors) GetByIP(ipv4 net.IP) *Neighbor {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if id, exists := n.ipIndex[ipv4.String()]; exists {
		return n.neighbors[id]
	}
	return nil
}

func (n *Neighbors) GetByMAC(mac net.HardwareAddr) *Neighbor {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if id, exists := n.macIndex[mac.String()]; exists {
		return n.neighbors[id]
	}
	return nil
}

func (n *Neighbors) All() []*Neighbor {
	n.mu.RLock()
	defer n.mu.RUnlock()

	result := make([]*Neighbor, 0, len(n.neighbors))
	for _, neighbor := range n.neighbors {
		result = append(result, neighbor)
	}
	return result
}
