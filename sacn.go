package tendrils

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fvbommel/sortorder"
)

type SACNNode struct {
	TypeID  string `json:"typeid"`
	Node    *Node  `json:"node"`
	Inputs  []int  `json:"inputs,omitempty"`
	Outputs []int  `json:"outputs,omitempty"`
}

func (t *Tendrils) getSACNNodes() []*SACNNode {
	t.nodes.mu.Lock()
	t.nodes.expireMulticastMemberships()
	t.nodes.mu.Unlock()

	t.sacnSources.Expire()

	t.nodes.mu.RLock()
	defer t.nodes.mu.RUnlock()

	nodeInputs := map[*Node][]int{}
	nodeOutputs := map[*Node][]int{}

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
			inputs := nodeInputs[membership.Node]
			if !containsInt(inputs, universe) {
				nodeInputs[membership.Node] = append(inputs, universe)
			}
		}
	}

	t.sacnSources.mu.RLock()
	for _, source := range t.sacnSources.sources {
		if source.SrcIP == nil {
			continue
		}
		node := t.nodes.getByIPLocked(source.SrcIP)
		if node == nil {
			continue
		}
		for _, u := range source.Universes {
			outputs := nodeOutputs[node]
			if !containsInt(outputs, u) {
				nodeOutputs[node] = append(outputs, u)
			}
		}
	}
	t.sacnSources.mu.RUnlock()

	allNodes := map[*Node]bool{}
	for node := range nodeInputs {
		allNodes[node] = true
	}
	for node := range nodeOutputs {
		allNodes[node] = true
	}

	result := make([]*SACNNode, 0, len(allNodes))
	for node := range allNodes {
		inputs := nodeInputs[node]
		outputs := nodeOutputs[node]
		sort.Ints(inputs)
		sort.Ints(outputs)
		result = append(result, &SACNNode{
			TypeID:  newTypeID("sacnnode"),
			Node:    node,
			Inputs:  inputs,
			Outputs: outputs,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return sortorder.NaturalLess(result[i].Node.DisplayName(), result[j].Node.DisplayName())
	})

	return result
}
