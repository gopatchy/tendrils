package tendrils

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/fvbommel/sortorder"
)

type MulticastGroup struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
}

type MulticastMembership struct {
	SourceIP string    `json:"source_ip"`
	Node     *Node     `json:"node,omitempty"`
	LastSeen time.Time `json:"last_seen"`
}

type MulticastMembershipMap map[string]*MulticastMembership

func (m MulticastMembershipMap) MarshalJSON() ([]byte, error) {
	members := make([]*MulticastMembership, 0, len(m))
	for _, membership := range m {
		members = append(members, membership)
	}
	sort.Slice(members, func(i, j int) bool {
		nameI := members[i].SourceIP
		if members[i].Node != nil && members[i].Node.DisplayName() != "" {
			nameI = members[i].Node.DisplayName()
		}
		nameJ := members[j].SourceIP
		if members[j].Node != nil && members[j].Node.DisplayName() != "" {
			nameJ = members[j].Node.DisplayName()
		}
		return sortorder.NaturalLess(nameI, nameJ)
	})
	return json.Marshal(members)
}

type MulticastGroupMembers struct {
	TypeID  string                 `json:"typeid"`
	Group   *MulticastGroup        `json:"group"`
	Members MulticastMembershipMap `json:"members"`
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

	groupKey := groupIP.String()
	sourceKey := sourceIP.String()

	gm := n.multicastGroups[groupKey]
	if gm == nil {
		gm = &MulticastGroupMembers{
			TypeID: newTypeID("mcastgroup"),
			Group: &MulticastGroup{
				Name: multicastGroupName(groupIP),
				IP:   groupKey,
			},
			Members: MulticastMembershipMap{},
		}
		n.multicastGroups[groupKey] = gm
	}

	membership := gm.Members[sourceKey]
	if membership == nil {
		membership = &MulticastMembership{
			SourceIP: sourceKey,
		}
		gm.Members[sourceKey] = membership
	}
	membership.Node = node
	membership.LastSeen = time.Now()
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
			groups = append(groups, net.ParseIP(gm.Group.IP))
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
