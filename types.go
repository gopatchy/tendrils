package tendrils

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/fvbommel/sortorder"
	"go.jetify.com/typeid"
)

func newTypeID(prefix string) string {
	tid, _ := typeid.WithPrefix(prefix)
	return tid.String()
}

type MAC string

func (m MAC) Parse() net.HardwareAddr {
	mac, _ := net.ParseMAC(string(m))
	return mac
}

func MACFrom(mac net.HardwareAddr) MAC {
	if mac == nil {
		return ""
	}
	return MAC(mac.String())
}

type IPSet map[string]bool

func (s IPSet) MarshalJSON() ([]byte, error) {
	ips := make([]string, 0, len(s))
	for ip := range s {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	return json.Marshal(ips)
}

func (s IPSet) Add(ip net.IP) {
	s[ip.String()] = true
}

func (s IPSet) Has(ip string) bool {
	return s[ip]
}

func (s IPSet) Slice() []string {
	ips := make([]string, 0, len(s))
	for ip := range s {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	return ips
}

type NameSet map[string]bool

func sortNamesByLength(names []string) {
	sort.Slice(names, func(i, j int) bool {
		if len(names[i]) != len(names[j]) {
			return len(names[i]) < len(names[j])
		}
		return names[i] < names[j]
	})
}

func (s NameSet) MarshalJSON() ([]byte, error) {
	names := make([]string, 0, len(s))
	for name := range s {
		names = append(names, name)
	}
	sortNamesByLength(names)
	return json.Marshal(names)
}

func (s NameSet) Add(name string) {
	s[name] = true
}

func (s NameSet) Has(name string) bool {
	return s[name]
}

type InterfaceMap map[string]*Interface

func (m InterfaceMap) MarshalJSON() ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return sortorder.NaturalLess(keys[i], keys[j])
	})
	ifaces := make([]*Interface, 0, len(m))
	for _, k := range keys {
		ifaces = append(ifaces, m[k])
	}
	return json.Marshal(ifaces)
}

type Interface struct {
	Name  string          `json:"name,omitempty"`
	MAC   MAC             `json:"mac"`
	IPs   IPSet           `json:"ips"`
	Stats *InterfaceStats `json:"stats,omitempty"`
}

type InterfaceStats struct {
	Speed     uint64    `json:"speed,omitempty"`
	InErrors  uint64    `json:"in_errors,omitempty"`
	OutErrors uint64    `json:"out_errors,omitempty"`
	PoE       *PoEStats `json:"poe,omitempty"`
}

type PoEStats struct {
	Power    float64 `json:"power"`
	MaxPower float64 `json:"max_power"`
}

type PoEBudget struct {
	Power    float64 `json:"power"`
	MaxPower float64 `json:"max_power"`
}

type Node struct {
	TypeID             string            `json:"typeid"`
	Names              NameSet           `json:"names"`
	Interfaces         InterfaceMap      `json:"interfaces"`
	MACTable           map[string]string `json:"-"`
	MACTableSize       int               `json:"mac_table_size,omitempty"`
	PoEBudget          *PoEBudget        `json:"poe_budget,omitempty"`
	IsDanteClockMaster bool              `json:"is_dante_clock_master,omitempty"`
	DanteTxChannels    string            `json:"dante_tx_channels,omitempty"`
	pollTrigger        chan struct{}
}

func (n *Node) WithInterface(ifaceKey string) *Node {
	if ifaceKey == "" {
		return n
	}
	iface, exists := n.Interfaces[ifaceKey]
	if !exists {
		return n
	}
	return &Node{
		TypeID:             n.TypeID,
		Names:              n.Names,
		Interfaces:         InterfaceMap{ifaceKey: iface},
		MACTableSize:       n.MACTableSize,
		PoEBudget:          n.PoEBudget,
		IsDanteClockMaster: n.IsDanteClockMaster,
		DanteTxChannels:    n.DanteTxChannels,
	}
}

func (i *Interface) String() string {
	var parts []string
	parts = append(parts, string(i.MAC))
	if i.Name != "" {
		parts = append(parts, fmt.Sprintf("(%s)", i.Name))
	}
	if len(i.IPs) > 0 {
		parts = append(parts, fmt.Sprintf("%v", i.IPs.Slice()))
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
	sortNamesByLength(names)
	return strings.Join(names, "/")
}

func (n *Node) FirstMAC() string {
	for _, iface := range n.Interfaces {
		if iface.MAC != "" {
			return string(iface.MAC)
		}
	}
	return "??"
}
