package tendrils

import (
	"fmt"
	"net"
	"time"
)

type MulticastGroup struct {
	IP net.IP
}

type MulticastMembership struct {
	Node     *Node
	LastSeen time.Time
}

type MulticastGroupMembers struct {
	Group   *MulticastGroup
	Members map[string]*MulticastMembership // source IP -> membership
}

func (g *MulticastGroup) Name() string {
	ip := g.IP.To4()
	if ip == nil {
		return g.IP.String()
	}

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
}

func (n *Nodes) GetMulticastGroupMembers(groupIP net.IP) []*Node {
	n.mu.RLock()
	defer n.mu.RUnlock()

	groupKey := groupIP.String()
	gm := n.multicastGroups[groupKey]
	if gm == nil {
		return nil
	}

	var members []*Node
	for _, membership := range gm.Members {
		if membership.Node != nil {
			members = append(members, membership.Node)
		}
	}
	return members
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
