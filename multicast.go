package tendrils

import (
	"fmt"
	"net"
	"sort"
	"time"
)

type MulticastGroup struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
}

func (g *MulticastGroup) IsDante() bool {
	ip := net.ParseIP(g.IP).To4()
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

func multicastGroupName(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ip.String()
	}

	switch ip.String() {
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

	if ip4[0] == 239 && ip4[1] == 255 {
		universe := int(ip4[2])*256 + int(ip4[3])
		if universe >= 1 && universe <= 63999 {
			return fmt.Sprintf("sacn:%d", universe)
		}
	}

	if ip4[0] == 239 && ip4[1] >= 69 && ip4[1] <= 71 {
		flowID := (int(ip4[1]-69) << 16) | (int(ip4[2]) << 8) | int(ip4[3])
		return fmt.Sprintf("dante-mcast:%d", flowID)
	}

	if ip4[0] == 239 && ip4[1] == 253 {
		flowID := (int(ip4[2]) << 8) | int(ip4[3])
		return fmt.Sprintf("dante-av:%d", flowID)
	}

	return ip.String()
}

func (n *Nodes) UpdateMulticastMembership(sourceIP, groupIP net.IP) {
	n.mu.Lock()
	defer n.mu.Unlock()

	node := n.getNodeByIPLocked(sourceIP)
	if node == nil {
		return
	}

	groupName := multicastGroupName(groupIP)

	if node.multicastLastSeen == nil {
		node.multicastLastSeen = map[string]time.Time{}
	}
	node.multicastLastSeen[groupName] = time.Now()

	if !containsString(node.MulticastGroups, groupName) {
		node.MulticastGroups = append(node.MulticastGroups, groupName)
		sort.Strings(node.MulticastGroups)
	}

	if len(groupName) > 5 && groupName[:5] == "sacn:" {
		var universe int
		if _, err := fmt.Sscanf(groupName, "sacn:%d", &universe); err == nil {
			if !containsInt(node.SACNInputs, universe) {
				node.SACNInputs = append(node.SACNInputs, universe)
				sort.Ints(node.SACNInputs)
			}
		}
	}
}

func (n *Nodes) RemoveMulticastMembership(sourceIP, groupIP net.IP) {
	n.mu.Lock()
	defer n.mu.Unlock()

	node := n.getNodeByIPLocked(sourceIP)
	if node == nil {
		return
	}

	groupName := multicastGroupName(groupIP)
	delete(node.multicastLastSeen, groupName)

	var groups []string
	for _, g := range node.MulticastGroups {
		if g != groupName {
			groups = append(groups, g)
		}
	}
	node.MulticastGroups = groups
}

func (n *Nodes) GetDanteMulticastGroups(deviceIP net.IP) []net.IP {
	n.mu.RLock()
	defer n.mu.RUnlock()

	node := n.getNodeByIPLocked(deviceIP)
	if node == nil {
		return nil
	}

	var groups []net.IP
	for _, groupName := range node.MulticastGroups {
		g := &MulticastGroup{Name: groupName}
		if g.IsDante() {
			ip := net.ParseIP(groupName)
			if ip != nil {
				groups = append(groups, ip)
			}
		}
	}
	return groups
}

func (n *Nodes) GetMulticastGroupMembers(groupIP net.IP) []*Node {
	n.mu.RLock()
	defer n.mu.RUnlock()

	groupName := multicastGroupName(groupIP)
	var members []*Node
	for _, node := range n.nodes {
		if containsString(node.MulticastGroups, groupName) {
			members = append(members, node)
		}
	}
	return members
}

func (n *Nodes) expireMulticastMemberships() {
	expireTime := time.Now().Add(-5 * time.Minute)
	for _, node := range n.nodes {
		if node.multicastLastSeen == nil {
			continue
		}
		var keepGroups []string
		var keepSACNInputs []int
		for _, groupName := range node.MulticastGroups {
			if lastSeen, ok := node.multicastLastSeen[groupName]; ok && !lastSeen.Before(expireTime) {
				keepGroups = append(keepGroups, groupName)
				if len(groupName) > 5 && groupName[:5] == "sacn:" {
					var universe int
					if _, err := fmt.Sscanf(groupName, "sacn:%d", &universe); err == nil {
						keepSACNInputs = append(keepSACNInputs, universe)
					}
				}
			} else {
				delete(node.multicastLastSeen, groupName)
			}
		}
		node.MulticastGroups = keepGroups
		sort.Ints(keepSACNInputs)
		node.SACNInputs = keepSACNInputs
	}
}

func (n *Nodes) mergeMulticast(keep, merge *Node) {
	if merge.multicastLastSeen == nil {
		return
	}
	if keep.multicastLastSeen == nil {
		keep.multicastLastSeen = map[string]time.Time{}
	}
	for groupName, lastSeen := range merge.multicastLastSeen {
		if existing, ok := keep.multicastLastSeen[groupName]; !ok || lastSeen.After(existing) {
			keep.multicastLastSeen[groupName] = lastSeen
		}
		if !containsString(keep.MulticastGroups, groupName) {
			keep.MulticastGroups = append(keep.MulticastGroups, groupName)
		}
		if len(groupName) > 5 && groupName[:5] == "sacn:" {
			var universe int
			if _, err := fmt.Sscanf(groupName, "sacn:%d", &universe); err == nil {
				if !containsInt(keep.SACNInputs, universe) {
					keep.SACNInputs = append(keep.SACNInputs, universe)
				}
			}
		}
	}
	sort.Strings(keep.MulticastGroups)
	sort.Ints(keep.SACNInputs)
}
