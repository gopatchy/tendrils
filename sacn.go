package tendrils

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fvbommel/sortorder"
)

type SACNNode struct {
	TypeID    string `json:"typeid"`
	Node      *Node  `json:"node"`
	Universes []int  `json:"universes"`
}

func (t *Tendrils) getSACNNodes() []*SACNNode {
	t.nodes.mu.Lock()
	t.nodes.expireMulticastMemberships()
	t.nodes.mu.Unlock()

	t.nodes.mu.RLock()
	defer t.nodes.mu.RUnlock()

	nodeUniverses := map[*Node][]int{}

	for _, gm := range t.nodes.multicastGroups {
		if !strings.HasPrefix(gm.Group.Name, "sacn:") {
			continue
		}

		var universe int
		if _, err := fmt.Sscanf(gm.Group.Name, "sacn:%d", &universe); err != nil {
			continue
		}

		for _, membership := range gm.Members {
			if membership.Node == nil {
				continue
			}
			universes := nodeUniverses[membership.Node]
			if !containsInt(universes, universe) {
				nodeUniverses[membership.Node] = append(universes, universe)
			}
		}
	}

	result := make([]*SACNNode, 0, len(nodeUniverses))
	for node, universes := range nodeUniverses {
		sort.Ints(universes)
		result = append(result, &SACNNode{
			TypeID:    newTypeID("sacnnode"),
			Node:      node,
			Universes: universes,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return sortorder.NaturalLess(result[i].Node.DisplayName(), result[j].Node.DisplayName())
	})

	return result
}
