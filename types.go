package tendrils

import (
	"fmt"
	"net"
	"sort"
	"strings"

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

type PoEBudget struct {
	Power    float64 // watts in use
	MaxPower float64 // watts total budget
}

type Node struct {
	Names              map[string]bool
	Interfaces         map[string]*Interface
	MACTable           map[string]string // peer MAC -> local interface name
	PoEBudget          *PoEBudget
	IsDanteClockMaster bool
	DanteTxChannels    string
	pollTrigger        chan struct{}
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

	return "[" + strings.Join(parts, " ") + "]"
}

func (n *Node) String() string {
	name := n.DisplayName()
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

	return strings.Join(parts, " ")
}

func (n *Node) DisplayName() string {
	if len(n.Names) == 0 {
		return ""
	}
	var names []string
	for name := range n.Names {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, "/")
}

func (n *Node) FirstMAC() string {
	for _, iface := range n.Interfaces {
		if iface.MAC != nil {
			return iface.MAC.String()
		}
	}
	return "??"
}
