package tendrils

import "fmt"

type Link struct {
	TypeID     string `json:"typeid"`
	NodeA      *Node  `json:"node_a"`
	InterfaceA string `json:"interface_a,omitempty"`
	NodeB      *Node  `json:"node_b"`
	InterfaceB string `json:"interface_b,omitempty"`
}

func (l *Link) String() string {
	nameA := l.NodeA.DisplayName()
	if nameA == "" {
		nameA = l.NodeA.FirstMAC()
	}
	nameB := l.NodeB.DisplayName()
	if nameB == "" {
		nameB = l.NodeB.FirstMAC()
	}
	sideA := nameA
	if l.InterfaceA != "" {
		sideA = nameA + ":" + l.InterfaceA
	}
	sideB := nameB
	if l.InterfaceB != "" {
		sideB = nameB + ":" + l.InterfaceB
	}
	return fmt.Sprintf("%s <-> %s", sideA, sideB)
}

func (n *Nodes) getDirectLinks() []*Link {
	macToNode := map[string]*Node{}
	for _, node := range n.nodes {
		for _, iface := range node.Interfaces {
			if iface.MAC != "" {
				macToNode[string(iface.MAC)] = node
			}
		}
	}

	seen := map[string]bool{}
	var links []*Link

	for _, target := range n.nodes {
		seenMACs := map[string]bool{}
		for _, iface := range target.Interfaces {
			if iface.MAC == "" {
				continue
			}
			mac := string(iface.MAC)
			if seenMACs[mac] {
				continue
			}
			seenMACs[mac] = true

			lastHop, lastPort := n.findLastHop(target, mac, macToNode)
			if lastHop == nil {
				continue
			}

			targetIface := n.findTargetInterface(target, lastHop, macToNode)
			key := makeLinkKey(lastHop, lastPort, target, targetIface)
			if !seen[key] {
				seen[key] = true
				links = append(links, &Link{
					TypeID:     newTypeID("link"),
					NodeA:      lastHop,
					InterfaceA: lastPort,
					NodeB:      target,
					InterfaceB: targetIface,
				})
			}
		}
	}

	return links
}

func (n *Nodes) findLastHop(target *Node, mac string, macToNode map[string]*Node) (*Node, string) {
	for _, node := range n.nodes {
		port, sees := node.MACTable[mac]
		if !sees || node == target {
			continue
		}

		if !n.hasCloserNode(node, target, mac, port, macToNode) {
			return node, port
		}
	}
	return nil, ""
}

func (n *Nodes) hasCloserNode(node, target *Node, mac, port string, macToNode map[string]*Node) bool {
	nodeMACs := map[string]bool{}
	for _, iface := range node.Interfaces {
		if iface.MAC != "" {
			nodeMACs[string(iface.MAC)] = true
		}
	}

	for otherMAC, otherPort := range node.MACTable {
		if otherPort != port {
			continue
		}
		otherNode := macToNode[otherMAC]
		if otherNode == nil || otherNode == node || otherNode == target {
			continue
		}

		targetPort, alsoSees := otherNode.MACTable[mac]
		if !alsoSees {
			continue
		}

		seesNodeOnSamePort := false
		for nodeMAC := range nodeMACs {
			if nodePort, seesNode := otherNode.MACTable[nodeMAC]; seesNode && nodePort == targetPort {
				seesNodeOnSamePort = true
				break
			}
		}

		if !seesNodeOnSamePort {
			return true
		}
	}
	return false
}

func (n *Nodes) findTargetInterface(target, lastHop *Node, macToNode map[string]*Node) string {
	for lastHopMAC, targetPort := range target.MACTable {
		if macToNode[lastHopMAC] == lastHop {
			return targetPort
		}
	}
	return ""
}

func makeLinkKey(nodeA *Node, ifaceA string, nodeB *Node, ifaceB string) string {
	ptrA := fmt.Sprintf("%p", nodeA)
	ptrB := fmt.Sprintf("%p", nodeB)
	if ptrA < ptrB {
		return ptrA + ":" + ifaceA + "-" + ptrB + ":" + ifaceB
	}
	return ptrB + ":" + ifaceB + "-" + ptrA + ":" + ifaceA
}
