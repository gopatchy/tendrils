package tendrils

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/fvbommel/sortorder"
	"go.jetify.com/typeid"
)

func newID(prefix string) string {
	tid, _ := typeid.WithPrefix(prefix)
	return tid.String()
}

type ArtNetUniverse int

func (u ArtNetUniverse) Net() int {
	return (int(u) >> 8) & 0x7f
}

func (u ArtNetUniverse) Subnet() int {
	return (int(u) >> 4) & 0x0f
}

func (u ArtNetUniverse) Universe() int {
	return int(u) & 0x0f
}

func (u ArtNetUniverse) String() string {
	return fmt.Sprintf("%d/%d/%d", u.Net(), u.Subnet(), u.Universe())
}

type ArtNetUniverseSet map[ArtNetUniverse]time.Time

func (s ArtNetUniverseSet) Add(u ArtNetUniverse) {
	s[u] = time.Now()
}

func (s ArtNetUniverseSet) Universes() []ArtNetUniverse {
	result := make([]ArtNetUniverse, 0, len(s))
	for u := range s {
		result = append(result, u)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func (s ArtNetUniverseSet) Expire(maxAge time.Duration) {
	expireTime := time.Now().Add(-maxAge)
	for u, lastSeen := range s {
		if lastSeen.Before(expireTime) {
			delete(s, u)
		}
	}
}

func (s ArtNetUniverseSet) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Universes())
}

type SACNUniverse int

func (u SACNUniverse) String() string {
	return fmt.Sprintf("%d", u)
}

type SACNUniverseSet map[SACNUniverse]time.Time

func (s SACNUniverseSet) Add(u SACNUniverse) {
	s[u] = time.Now()
}

func (s SACNUniverseSet) Universes() []SACNUniverse {
	result := make([]SACNUniverse, 0, len(s))
	for u := range s {
		result = append(result, u)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func (s SACNUniverseSet) Expire(maxAge time.Duration) {
	expireTime := time.Now().Add(-maxAge)
	for u, lastSeen := range s {
		if lastSeen.Before(expireTime) {
			delete(s, u)
		}
	}
}

func (s SACNUniverseSet) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Universes())
}

type MulticastGroupID int

const (
	MulticastUnknown MulticastGroupID = iota
	MulticastMDNS
	MulticastPTP
	MulticastPTPAnnounce
	MulticastPTPSync
	MulticastPTPDelay
	MulticastSAP
	MulticastShureSLP
	MulticastSSDP
	MulticastSLP
	MulticastAdminScopedBroadcast
)

type MulticastGroup struct {
	ID       MulticastGroupID
	SACNUniverse  SACNUniverse
	DanteFlow     int
	DanteAV       int
	RawIP         string
}

func (g MulticastGroup) String() string {
	switch g.ID {
	case MulticastMDNS:
		return "mdns"
	case MulticastPTP:
		return "ptp"
	case MulticastPTPAnnounce:
		return "ptp-announce"
	case MulticastPTPSync:
		return "ptp-sync"
	case MulticastPTPDelay:
		return "ptp-delay"
	case MulticastSAP:
		return "sap"
	case MulticastShureSLP:
		return "shure-slp"
	case MulticastSSDP:
		return "ssdp"
	case MulticastSLP:
		return "slp"
	case MulticastAdminScopedBroadcast:
		return "admin-scoped-broadcast"
	}
	if g.SACNUniverse > 0 {
		return fmt.Sprintf("sacn:%d", g.SACNUniverse)
	}
	if g.DanteFlow > 0 {
		return fmt.Sprintf("dante-mcast:%d", g.DanteFlow)
	}
	if g.DanteAV > 0 {
		return fmt.Sprintf("dante-av:%d", g.DanteAV)
	}
	return g.RawIP
}

func (g MulticastGroup) MarshalJSON() ([]byte, error) {
	return json.Marshal(g.String())
}

func (g MulticastGroup) IsDante() bool {
	return g.DanteFlow > 0 || g.DanteAV > 0
}

func (g MulticastGroup) IsSACN() bool {
	return g.SACNUniverse > 0
}

func ParseMulticastGroup(ip net.IP) MulticastGroup {
	ip4 := ip.To4()
	if ip4 == nil {
		return MulticastGroup{RawIP: ip.String()}
	}

	switch ip.String() {
	case "224.0.0.251":
		return MulticastGroup{ID: MulticastMDNS}
	case "224.0.1.129":
		return MulticastGroup{ID: MulticastPTP}
	case "224.0.1.130":
		return MulticastGroup{ID: MulticastPTPAnnounce}
	case "224.0.1.131":
		return MulticastGroup{ID: MulticastPTPSync}
	case "224.0.1.132":
		return MulticastGroup{ID: MulticastPTPDelay}
	case "224.2.127.254":
		return MulticastGroup{ID: MulticastSAP}
	case "239.255.254.253":
		return MulticastGroup{ID: MulticastShureSLP}
	case "239.255.255.250":
		return MulticastGroup{ID: MulticastSSDP}
	case "239.255.255.253":
		return MulticastGroup{ID: MulticastSLP}
	case "239.255.255.255":
		return MulticastGroup{ID: MulticastAdminScopedBroadcast}
	}

	if ip4[0] == 239 && ip4[1] == 255 {
		universe := int(ip4[2])*256 + int(ip4[3])
		if universe >= 1 && universe <= 63999 {
			return MulticastGroup{SACNUniverse: SACNUniverse(universe)}
		}
	}

	if ip4[0] == 239 && ip4[1] >= 69 && ip4[1] <= 71 {
		flowID := (int(ip4[1]-69) << 16) | (int(ip4[2]) << 8) | int(ip4[3])
		return MulticastGroup{DanteFlow: flowID}
	}

	if ip4[0] == 239 && ip4[1] == 253 {
		flowID := (int(ip4[2]) << 8) | int(ip4[3])
		return MulticastGroup{DanteAV: flowID}
	}

	return MulticastGroup{RawIP: ip.String()}
}

type MulticastMembershipSet map[MulticastGroup]time.Time

func (s MulticastMembershipSet) Add(group MulticastGroup) {
	s[group] = time.Now()
}

func (s MulticastMembershipSet) Remove(group MulticastGroup) {
	delete(s, group)
}

func (s MulticastMembershipSet) Groups() []MulticastGroup {
	result := make([]MulticastGroup, 0, len(s))
	for g := range s {
		result = append(result, g)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].String() < result[j].String()
	})
	return result
}

func (s MulticastMembershipSet) SACNInputs() []SACNUniverse {
	var result []SACNUniverse
	for g := range s {
		if g.IsSACN() {
			result = append(result, g.SACNUniverse)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func (s MulticastMembershipSet) Expire(maxAge time.Duration) {
	expireTime := time.Now().Add(-maxAge)
	for g, lastSeen := range s {
		if lastSeen.Before(expireTime) {
			delete(s, g)
		}
	}
}

func (s MulticastMembershipSet) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Groups())
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
	IPs   IPSet           `json:"ips,omitempty"`
	Stats *InterfaceStats `json:"stats,omitempty"`
}

func (i *Interface) MarshalJSON() ([]byte, error) {
	type ifaceJSON struct {
		Name  string          `json:"name,omitempty"`
		MAC   MAC             `json:"mac"`
		IPs   []string        `json:"ips,omitempty"`
		Stats *InterfaceStats `json:"stats,omitempty"`
	}
	var ips []string
	if len(i.IPs) > 0 {
		ips = i.IPs.Slice()
	}
	return json.Marshal(ifaceJSON{
		Name:  i.Name,
		MAC:   i.MAC,
		IPs:   ips,
		Stats: i.Stats,
	})
}

type InterfaceStats struct {
	Speed        uint64    `json:"speed,omitempty"`
	InErrors     uint64    `json:"in_errors,omitempty"`
	OutErrors    uint64    `json:"out_errors,omitempty"`
	InPktsRate   float64   `json:"in_pkts_rate,omitempty"`
	OutPktsRate  float64   `json:"out_pkts_rate,omitempty"`
	InBytesRate  float64   `json:"in_bytes_rate,omitempty"`
	OutBytesRate float64   `json:"out_bytes_rate,omitempty"`
	PoE          *PoEStats `json:"poe,omitempty"`
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

func (s *InterfaceStats) MarshalJSON() ([]byte, error) {
	type statsJSON struct {
		Speed        uint64    `json:"speed,omitempty"`
		InErrors     uint64    `json:"in_errors,omitempty"`
		OutErrors    uint64    `json:"out_errors,omitempty"`
		InPktsRate   float64   `json:"in_pkts_rate,omitempty"`
		OutPktsRate  float64   `json:"out_pkts_rate,omitempty"`
		InBytesRate  float64   `json:"in_bytes_rate,omitempty"`
		OutBytesRate float64   `json:"out_bytes_rate,omitempty"`
		PoE          *PoEStats `json:"poe,omitempty"`
	}
	return json.Marshal(statsJSON{
		Speed:        s.Speed,
		InErrors:     s.InErrors,
		OutErrors:    s.OutErrors,
		InPktsRate:   round2(s.InPktsRate),
		OutPktsRate:  round2(s.OutPktsRate),
		InBytesRate:  round2(s.InBytesRate),
		OutBytesRate: round2(s.OutBytesRate),
		PoE:          s.PoE,
	})
}

type PoEStats struct {
	Power    float64 `json:"power"`
	MaxPower float64 `json:"max_power"`
}

type PoEBudget struct {
	Power    float64 `json:"power"`
	MaxPower float64 `json:"max_power"`
}

type DanteFlows struct {
	Tx       []*DantePeer `json:"tx,omitempty"`
	Rx       []*DantePeer `json:"rx,omitempty"`
	lastSeen time.Time
}

func (f *DanteFlows) Expire(maxAge time.Duration) bool {
	if f.lastSeen.IsZero() {
		return false
	}
	return time.Since(f.lastSeen) > maxAge
}

type Node struct {
	ID                    string                 `json:"id"`
	Names                 NameSet                `json:"names"`
	Interfaces            InterfaceMap           `json:"interfaces"`
	MACTable              map[string]string      `json:"-"`
	PoEBudget             *PoEBudget             `json:"poe_budget,omitempty"`
	DanteTxChannels       int                    `json:"dante_tx_channels,omitempty"`
	DanteClockMasterSeen  time.Time              `json:"-"`
	DanteFlows            *DanteFlows            `json:"dante_flows,omitempty"`
	MulticastGroups       MulticastMembershipSet `json:"multicast_groups,omitempty"`
	ArtNetInputs          ArtNetUniverseSet      `json:"artnet_inputs,omitempty"`
	ArtNetOutputs         ArtNetUniverseSet      `json:"artnet_outputs,omitempty"`
	SACNUnicastInputs     SACNUniverseSet        `json:"sacn_unicast_inputs,omitempty"`
	SACNOutputs           SACNUniverseSet        `json:"sacn_outputs,omitempty"`
	Unreachable           bool                   `json:"unreachable,omitempty"`
	errors                *ErrorTracker
	pollTrigger           chan struct{}
	cancelFunc            context.CancelFunc
}

func (n *Node) IsDanteClockMaster() bool {
	return !n.DanteClockMasterSeen.IsZero() && time.Since(n.DanteClockMasterSeen) < 5*time.Minute
}

func (n *Node) SetUnreachable(unreachable bool) bool {
	if n.Unreachable == unreachable {
		return false
	}
	n.Unreachable = unreachable
	if n.errors != nil {
		if unreachable {
			n.errors.AddUnreachable(n)
		} else {
			n.errors.RemoveUnreachable(n)
		}
	}
	return true
}

func (n *Node) SetInterfaceStats(portName string, stats *InterfaceStats) {
	iface := n.Interfaces[portName]
	if iface == nil {
		return
	}

	oldStats := iface.Stats
	iface.Stats = stats

	if n.errors == nil {
		return
	}

	var inDelta, outDelta uint64
	if oldStats != nil {
		if stats.InErrors > oldStats.InErrors {
			inDelta = stats.InErrors - oldStats.InErrors
		}
		if stats.OutErrors > oldStats.OutErrors {
			outDelta = stats.OutErrors - oldStats.OutErrors
		}
	}
	if inDelta > 0 || outDelta > 0 {
		n.errors.AddPortError(n, portName, stats, inDelta, outDelta)
	}

	if stats.Speed > 0 {
		maxBytesRate := stats.InBytesRate
		if stats.OutBytesRate > maxBytesRate {
			maxBytesRate = stats.OutBytesRate
		}
		speedBytes := float64(stats.Speed) / 8.0
		utilization := (maxBytesRate / speedBytes) * 100.0

		var oldUtilization float64
		if oldStats != nil && oldStats.Speed > 0 {
			oldMax := oldStats.InBytesRate
			if oldStats.OutBytesRate > oldMax {
				oldMax = oldStats.OutBytesRate
			}
			oldUtilization = (oldMax / (float64(oldStats.Speed) / 8.0)) * 100.0
		}

		if oldUtilization < 70.0 && utilization >= 70.0 {
			n.errors.AddUtilizationError(n, portName, utilization)
		}
	}
}

func (n *Node) MACTableSize() int {
	return len(n.MACTable)
}

func (n *Node) SACNInputs() []SACNUniverse {
	if n.MulticastGroups == nil {
		return nil
	}
	return n.MulticastGroups.SACNInputs()
}

type DanteFlowStatus uint8

const (
	DanteFlowUnsubscribed DanteFlowStatus = 0x00
	DanteFlowNoSource     DanteFlowStatus = 0x01
	DanteFlowActive       DanteFlowStatus = 0x09
)

func (s DanteFlowStatus) String() string {
	switch s {
	case DanteFlowActive:
		return "active"
	case DanteFlowNoSource:
		return "no-source"
	default:
		return ""
	}
}

func (s DanteFlowStatus) MarshalJSON() ([]byte, error) {
	str := s.String()
	if str == "" {
		return []byte("null"), nil
	}
	return json.Marshal(str)
}

type DanteChannelType uint16

const (
	DanteChannelUnknown DanteChannelType = 0
	DanteChannelAudio   DanteChannelType = 0x000f
	DanteChannelAudio2  DanteChannelType = 0x0006
	DanteChannelVideo   DanteChannelType = 0x000e
)

func (t DanteChannelType) String() string {
	switch t {
	case DanteChannelAudio, DanteChannelAudio2:
		return "audio"
	case DanteChannelVideo:
		return "video"
	default:
		return ""
	}
}

func (t DanteChannelType) MarshalJSON() ([]byte, error) {
	str := t.String()
	if str == "" {
		return []byte("null"), nil
	}
	return json.Marshal(str)
}

type DanteChannel struct {
	TxChannel string           `json:"tx_channel"`
	RxChannel int              `json:"rx_channel"`
	Type      DanteChannelType `json:"type,omitempty"`
	Status    DanteFlowStatus  `json:"status,omitempty"`
}

type DantePeer struct {
	Node     *Node           `json:"node"`
	Channels []*DanteChannel `json:"channels,omitempty"`
}

func (p *DantePeer) MarshalJSON() ([]byte, error) {
	type peerJSON struct {
		NodeID   string          `json:"node_id"`
		Channels []*DanteChannel `json:"channels,omitempty"`
	}
	return json.Marshal(peerJSON{
		NodeID:   p.Node.ID,
		Channels: p.Channels,
	})
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
		ID:                   n.ID,
		Names:                n.Names,
		Interfaces:           InterfaceMap{ifaceKey: iface},
		MACTable:             n.MACTable,
		PoEBudget:            n.PoEBudget,
		DanteClockMasterSeen: n.DanteClockMasterSeen,
		DanteTxChannels:      n.DanteTxChannels,
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

	if s.InBytesRate > 0 || s.OutBytesRate > 0 {
		parts = append(parts, fmt.Sprintf("%.0f/%.0fB/s", s.InBytesRate, s.OutBytesRate))
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
	if len(n.Names) > 0 {
		var names []string
		for name := range n.Names {
			names = append(names, name)
		}
		sortNamesByLength(names)
		return strings.Join(names, "/")
	}
	for _, iface := range n.Interfaces {
		for ip := range iface.IPs {
			return ip
		}
	}
	for _, iface := range n.Interfaces {
		if iface.MAC != "" {
			return string(iface.MAC)
		}
	}
	return ""
}

func (n *Node) FirstMAC() string {
	for _, iface := range n.Interfaces {
		if iface.MAC != "" {
			return string(iface.MAC)
		}
	}
	return ""
}

func (n *Node) FirstIP() string {
	for _, iface := range n.Interfaces {
		for ip := range iface.IPs {
			return ip
		}
	}
	return ""
}
