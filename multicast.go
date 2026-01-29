package tendrils

import (
	"net"
	"time"
)

func (n *Nodes) UpdateMulticastMembership(sourceIP, groupIP net.IP) {
	n.mu.Lock()
	defer n.mu.Unlock()

	node := n.getNodeByIPLocked(sourceIP)
	if node == nil {
		return
	}

	group := ParseMulticastGroup(groupIP)

	if node.MulticastGroups == nil {
		node.MulticastGroups = MulticastMembershipSet{}
	}
	node.MulticastGroups.Add(group)
}

func (n *Nodes) RemoveMulticastMembership(sourceIP, groupIP net.IP) {
	n.mu.Lock()
	defer n.mu.Unlock()

	node := n.getNodeByIPLocked(sourceIP)
	if node == nil {
		return
	}

	if node.MulticastGroups == nil {
		return
	}

	group := ParseMulticastGroup(groupIP)
	node.MulticastGroups.Remove(group)
}

func (n *Nodes) GetDanteMulticastGroups(deviceIP net.IP) []net.IP {
	n.mu.RLock()
	defer n.mu.RUnlock()

	node := n.getNodeByIPLocked(deviceIP)
	if node == nil || node.MulticastGroups == nil {
		return nil
	}

	var groups []net.IP
	for _, group := range node.MulticastGroups.Groups() {
		if group.IsDante() {
			ip := net.ParseIP(group.String())
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

	group := ParseMulticastGroup(groupIP)
	groupKey := group.String()
	var members []*Node
	for _, node := range n.nodes {
		if node.MulticastGroups == nil {
			continue
		}
		if _, exists := node.MulticastGroups[groupKey]; exists {
			members = append(members, node)
		}
	}
	return members
}

func (n *Nodes) expireMulticastMemberships() {
	for _, node := range n.nodes {
		if node.MulticastGroups != nil {
			node.MulticastGroups.Expire(5 * time.Minute)
		}
	}
}

func (n *Nodes) mergeMulticast(keep, merge *Node) {
	if merge.MulticastGroups == nil {
		return
	}
	if keep.MulticastGroups == nil {
		keep.MulticastGroups = MulticastMembershipSet{}
	}
	for key, membership := range merge.MulticastGroups {
		if existing, ok := keep.MulticastGroups[key]; !ok || membership.LastSeen.After(existing.LastSeen) {
			keep.MulticastGroups[key] = membership
		}
	}
}
