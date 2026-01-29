package tendrils

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fvbommel/sortorder"
)

const (
	danteControlPort = 4440
	ptpAnnounceAddr  = "224.0.1.129:319"
)

func (t *Tendrils) listenDante(ctx context.Context, iface net.Interface) {
	go t.listenPTP(ctx, iface)
}

func (t *Tendrils) listenPTP(ctx context.Context, iface net.Interface) {
	addr, err := net.ResolveUDPAddr("udp4", ptpAnnounceAddr)
	if err != nil {
		return
	}

	conn, err := net.ListenMulticastUDP("udp4", &iface, addr)
	if err != nil {
		if t.DebugDante {
			log.Printf("[dante] %s: failed to listen ptp: %v", iface.Name, err)
		}
		return
	}
	defer conn.Close()

	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			continue
		}

		t.handlePTPPacket(iface.Name, src.IP, buf[:n])
	}
}

func (t *Tendrils) handlePTPPacket(ifaceName string, srcIP net.IP, data []byte) {
	if len(data) < 34 {
		return
	}

	messageType := data[0] & 0x0f
	if messageType != 0x0b {
		return
	}

	if len(data) < 64 {
		return
	}

	clockClass := data[48]
	clockAccuracy := data[49]
	priority1 := data[47]
	priority2 := data[51]

	if t.DebugDante {
		log.Printf("[dante] %s: ptp announce from %s class=%d accuracy=%d p1=%d p2=%d",
			ifaceName, srcIP, clockClass, clockAccuracy, priority1, priority2)
	}

	t.nodes.SetDanteClockMaster(srcIP)
}

func (n *Nodes) UpdateDanteTxChannels(name string, ip net.IP, channels string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	node := n.getNodeByIPLocked(ip)
	if node == nil {
		return
	}
	node.DanteTxChannels = channels
}

func (n *Nodes) GetDanteTxDeviceInGroup(groupIP net.IP) *Node {
	n.mu.RLock()
	defer n.mu.RUnlock()

	groupName := multicastGroupName(groupIP)
	for _, node := range n.nodes {
		if node.DanteTxChannels != "" && containsString(node.MulticastGroups, groupName) {
			return node
		}
	}
	return nil
}

var danteSeqID uint32

func containsString(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
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
	return json.Marshal(s.String())
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

type DanteSubscription struct {
	RxChannel     int
	TxDeviceName  string
	TxChannelName string
	ChannelType   DanteChannelType
	FlowStatus    DanteFlowStatus
}

type DanteDeviceInfo struct {
	IP             net.IP
	Name           string
	RxChannelCount int
	TxChannelCount int
	Subscriptions  []DanteSubscription
	HasMulticast   bool
}

func (n *Nodes) UpdateDanteFlow(source, subscriber *Node, channelInfo string, flowStatus DanteFlowStatus) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.updateDanteTx(source, subscriber, channelInfo, flowStatus)
	n.updateDanteRx(subscriber, source, channelInfo, flowStatus)

	source.danteLastSeen = time.Now()
	subscriber.danteLastSeen = time.Now()
}

func (n *Nodes) updateDanteTx(source, subscriber *Node, channelInfo string, flowStatus DanteFlowStatus) {
	var peer *DantePeer
	for _, p := range source.DanteTx {
		if p.Node == subscriber {
			peer = p
			break
		}
	}
	if peer == nil {
		peer = &DantePeer{
			Node:   subscriber,
			Status: map[string]string{},
		}
		source.DanteTx = append(source.DanteTx, peer)
	}

	if channelInfo != "" && !containsString(peer.Channels, channelInfo) {
		peer.Channels = append(peer.Channels, channelInfo)
		sort.Strings(peer.Channels)
	}
	if channelInfo != "" {
		peer.Status[channelInfo] = flowStatus.String()
	}

	sort.Slice(source.DanteTx, func(i, j int) bool {
		return sortorder.NaturalLess(source.DanteTx[i].Node.DisplayName(), source.DanteTx[j].Node.DisplayName())
	})
}

func (n *Nodes) updateDanteRx(subscriber, source *Node, channelInfo string, flowStatus DanteFlowStatus) {
	var peer *DantePeer
	for _, p := range subscriber.DanteRx {
		if p.Node == source {
			peer = p
			break
		}
	}
	if peer == nil {
		peer = &DantePeer{
			Node:   source,
			Status: map[string]string{},
		}
		subscriber.DanteRx = append(subscriber.DanteRx, peer)
	}

	if channelInfo != "" && !containsString(peer.Channels, channelInfo) {
		peer.Channels = append(peer.Channels, channelInfo)
		sort.Strings(peer.Channels)
	}
	if channelInfo != "" {
		peer.Status[channelInfo] = flowStatus.String()
	}

	sort.Slice(subscriber.DanteRx, func(i, j int) bool {
		return sortorder.NaturalLess(subscriber.DanteRx[i].Node.DisplayName(), subscriber.DanteRx[j].Node.DisplayName())
	})
}

func (n *Nodes) expireDante() {
	expireTime := time.Now().Add(-5 * time.Minute)
	for _, node := range n.nodes {
		if !node.danteLastSeen.IsZero() && node.danteLastSeen.Before(expireTime) {
			node.DanteTx = nil
			node.DanteRx = nil
			node.danteLastSeen = time.Time{}
		}
	}
}

func (n *Nodes) mergeDante(keep, merge *Node) {
	for _, peer := range merge.DanteTx {
		var existing *DantePeer
		for _, p := range keep.DanteTx {
			if p.Node == peer.Node {
				existing = p
				break
			}
		}
		if existing == nil {
			keep.DanteTx = append(keep.DanteTx, peer)
		} else {
			for _, ch := range peer.Channels {
				if !containsString(existing.Channels, ch) {
					existing.Channels = append(existing.Channels, ch)
				}
			}
			for ch, status := range peer.Status {
				existing.Status[ch] = status
			}
		}
	}

	for _, peer := range merge.DanteRx {
		var existing *DantePeer
		for _, p := range keep.DanteRx {
			if p.Node == peer.Node {
				existing = p
				break
			}
		}
		if existing == nil {
			keep.DanteRx = append(keep.DanteRx, peer)
		} else {
			for _, ch := range peer.Channels {
				if !containsString(existing.Channels, ch) {
					existing.Channels = append(existing.Channels, ch)
				}
			}
			for ch, status := range peer.Status {
				existing.Status[ch] = status
			}
		}
	}

	if merge.danteLastSeen.After(keep.danteLastSeen) {
		keep.danteLastSeen = merge.danteLastSeen
	}

	for _, node := range n.nodes {
		for _, peer := range node.DanteTx {
			if peer.Node == merge {
				peer.Node = keep
			}
		}
		for _, peer := range node.DanteRx {
			if peer.Node == merge {
				peer.Node = keep
			}
		}
	}
}

func (n *Nodes) logDante() {
	type channelFlow struct {
		sourceName  string
		txCh        string
		rxName      string
		rxCh        string
		channelType string
		down        bool
	}
	var allChannelFlows []channelFlow
	var allNoChannelFlows []string

	for _, node := range n.nodes {
		if len(node.DanteTx) == 0 {
			continue
		}
		sourceName := node.DisplayName()
		if sourceName == "" {
			sourceName = "??"
		}

		for _, peer := range node.DanteTx {
			subName := peer.Node.DisplayName()
			if subName == "" {
				subName = "??"
			}
			if len(peer.Channels) == 0 {
				allNoChannelFlows = append(allNoChannelFlows, fmt.Sprintf("%s -> %s", sourceName, subName))
			} else {
				for _, ch := range peer.Channels {
					parts := strings.Split(ch, "->")
					if len(parts) == 2 {
						rxPart := parts[1]
						chType := ""
						if idx := strings.LastIndex(rxPart, ":"); idx != -1 {
							chType = rxPart[idx+1:]
							rxPart = rxPart[:idx]
						}
						allChannelFlows = append(allChannelFlows, channelFlow{
							sourceName:  sourceName,
							txCh:        parts[0],
							rxName:      subName,
							rxCh:        rxPart,
							channelType: chType,
							down:        peer.Status[ch] == "no-source",
						})
					} else {
						allNoChannelFlows = append(allNoChannelFlows, fmt.Sprintf("%s -> %s[%s]", sourceName, subName, ch))
					}
				}
			}
		}
	}

	totalFlows := len(allChannelFlows) + len(allNoChannelFlows)
	if totalFlows == 0 {
		return
	}

	log.Printf("[sigusr1] ================ %d dante flows ================", totalFlows)

	sort.Slice(allChannelFlows, func(i, j int) bool {
		if allChannelFlows[i].sourceName != allChannelFlows[j].sourceName {
			return sortorder.NaturalLess(allChannelFlows[i].sourceName, allChannelFlows[j].sourceName)
		}
		if allChannelFlows[i].txCh != allChannelFlows[j].txCh {
			return sortorder.NaturalLess(allChannelFlows[i].txCh, allChannelFlows[j].txCh)
		}
		return sortorder.NaturalLess(allChannelFlows[i].rxName, allChannelFlows[j].rxName)
	})
	sort.Strings(allNoChannelFlows)

	for _, cf := range allChannelFlows {
		suffix := ""
		if cf.down {
			suffix = " DOWN"
		}
		if cf.channelType != "" {
			log.Printf("[sigusr1]   %s[%s] -> %s[%s] (%s)%s", cf.sourceName, cf.txCh, cf.rxName, cf.rxCh, cf.channelType, suffix)
		} else {
			log.Printf("[sigusr1]   %s[%s] -> %s[%s]%s", cf.sourceName, cf.txCh, cf.rxName, cf.rxCh, suffix)
		}
	}
	for _, flow := range allNoChannelFlows {
		log.Printf("[sigusr1]   %s", flow)
	}
}

func nextDanteSeq() uint16 {
	return uint16(atomic.AddUint32(&danteSeqID, 1))
}

func (t *Tendrils) queryDanteDevice(ip net.IP) *DanteDeviceInfo {
	return t.queryDanteDeviceWithPort(ip, danteControlPort)
}

func (t *Tendrils) queryDanteDeviceWithPort(ip net.IP, port int) *DanteDeviceInfo {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: ip, Port: port})
	if err != nil {
		if t.DebugDante {
			log.Printf("[dante] %s:%d: dial failed: %v", ip, port, err)
		}
		return nil
	}
	defer conn.Close()

	info := &DanteDeviceInfo{IP: ip}

	if rxCount, txCount := t.queryDanteChannelCount(conn, ip); rxCount > 0 || txCount > 0 {
		info.RxChannelCount = rxCount
		info.TxChannelCount = txCount
	}

	if name := t.queryDanteDeviceName(conn, ip); name != "" {
		info.Name = name
	}

	if info.RxChannelCount > 0 || info.TxChannelCount > 0 {
		info.Subscriptions, info.HasMulticast = t.queryDanteSubscriptions(conn, ip, info.RxChannelCount, info.TxChannelCount)
		if t.DebugDante {
			log.Printf("[dante] %s: 0x3000 returned %d subscriptions, hasMulticast=%v", ip, len(info.Subscriptions), info.HasMulticast)
		}
		if info.RxChannelCount > 0 {
			subs3400 := t.queryDanteSubscriptions3400(conn, ip, info.RxChannelCount)
			if len(subs3400) > 0 {
				info.Subscriptions = subs3400
			}
		}
	}

	if info.TxChannelCount > 0 {
		t.queryDanteTxChannels(conn, ip, info.TxChannelCount)
		t.nodes.UpdateDanteTxChannels(info.Name, ip, fmt.Sprintf("%d", info.TxChannelCount))
	}

	return info
}

func buildDantePacket(packetType byte, cmd uint16, args []byte) []byte {
	seq := nextDanteSeq()
	totalLen := 10 + len(args)

	pkt := make([]byte, totalLen)
	pkt[0] = packetType
	pkt[1] = byte(seq & 0xff)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	if packetType == 0x27 {
		binary.BigEndian.PutUint16(pkt[4:6], 0x1300|seq)
	} else {
		binary.BigEndian.PutUint16(pkt[4:6], seq)
	}
	binary.BigEndian.PutUint16(pkt[6:8], cmd)
	copy(pkt[10:], args)

	return pkt
}

func (t *Tendrils) sendDanteCommand(conn *net.UDPConn, ip net.IP, cmd uint16, args []byte) []byte {
	pkt := buildDantePacket(0x27, cmd, args)

	conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	_, err := conn.Write(pkt)
	if err != nil {
		if t.DebugDante {
			log.Printf("[dante] %s: write failed: %v", ip, err)
		}
		return nil
	}

	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}

	if t.DebugDante {
		log.Printf("[dante] %s: cmd 0x%04x response (%d bytes): %x", ip, cmd, n, buf[:n])
	}

	return buf[:n]
}

func (t *Tendrils) sendDanteCommand28(conn *net.UDPConn, ip net.IP, cmd uint16, args []byte) []byte {
	pkt := buildDantePacket(0x28, cmd, args)

	conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	_, err := conn.Write(pkt)
	if err != nil {
		return nil
	}

	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}

	return buf[:n]
}

func (t *Tendrils) queryDanteDeviceName(conn *net.UDPConn, ip net.IP) string {
	resp := t.sendDanteCommand(conn, ip, 0x1003, nil)
	if resp == nil || len(resp) < 40 {
		return ""
	}

	for i := 40; i < len(resp)-4; i++ {
		if resp[i] >= 'A' && resp[i] <= 'Z' {
			end := i
			for end < len(resp) && resp[end] != 0 && resp[end] >= 0x20 && resp[end] < 0x7f {
				end++
			}
			if end-i >= 4 && end-i < 40 {
				name := string(resp[i:end])
				if name != "Audinate DCM" && !strings.HasPrefix(name, "Audinate") {
					if t.DebugDante {
						log.Printf("[dante] %s: device name: %q", ip, name)
					}
					return name
				}
			}
		}
	}

	return ""
}

func (t *Tendrils) queryDanteChannelCount(conn *net.UDPConn, ip net.IP) (int, int) {
	resp := t.sendDanteCommand(conn, ip, 0x1000, nil)
	if resp == nil || len(resp) < 16 {
		return 0, 0
	}

	txCount := int(binary.BigEndian.Uint16(resp[12:14]))
	rxCount := int(binary.BigEndian.Uint16(resp[14:16]))

	return rxCount, txCount
}

func (t *Tendrils) queryDanteTxChannels(conn *net.UDPConn, ip net.IP, txCount int) {
	if txCount == 0 {
		return
	}

	pagesNeeded := (txCount + 15) / 16
	for page := 0; page < pagesNeeded; page++ {
		pageNum := byte(page + 1)
		args := []byte{0x00, 0x01, 0x00, pageNum, 0x00, 0x00}

		resp := t.sendDanteCommand(conn, ip, 0x2000, args)
		if t.DebugDante {
			if resp == nil {
				log.Printf("[dante] %s: tx channels 0x2000 page %d: no response", ip, page)
			} else {
				log.Printf("[dante] %s: tx channels 0x2000 page %d (%d bytes): %x", ip, page, len(resp), resp)
			}
		}
	}
}

func (t *Tendrils) queryDanteSubscriptions(conn *net.UDPConn, ip net.IP, rxCount, txCount int) ([]DanteSubscription, bool) {
	if rxCount == 0 {
		return nil, false
	}

	var subscriptions []DanteSubscription
	hasMulticast := false

	pagesNeeded := (rxCount + 15) / 16
	for page := 0; page < pagesNeeded; page++ {
		pageNum := byte(page + 1)
		args := []byte{0x00, 0x01, 0x00, pageNum, 0x00, 0x00}

		resp := t.sendDanteCommand(conn, ip, 0x3000, args)
		if resp == nil || len(resp) < 14 {
			continue
		}

		status := binary.BigEndian.Uint16(resp[8:10])
		if status != 0x0001 {
			if t.DebugDante {
				log.Printf("[dante] %s: 0x3000 status=0x%04x", ip, status)
			}
			continue
		}

		subCount := int(resp[10])

		recordType := binary.BigEndian.Uint16(resp[14:16])
		isMulticast := recordType == 0x000e
		hasMulticast = hasMulticast || isMulticast

		if isMulticast {
			if t.DebugDante {
				stringTableStart := 12 + subCount*20
				if stringTableStart < len(resp) {
					log.Printf("[dante] %s: multicast string table at offset %d: %x", ip, stringTableStart, resp[stringTableStart:])
				}
			}
			recordOffset := 12
			for idx := 0; idx < subCount; idx++ {
				if recordOffset+20 > len(resp) {
					break
				}

				if t.DebugDante {
					log.Printf("[dante] %s: multicast record %d at offset %d: %x", ip, idx, recordOffset, resp[recordOffset:recordOffset+20])
				}

				rxChannelNum := int(binary.BigEndian.Uint16(resp[recordOffset : recordOffset+2]))
				txDeviceOffset := int(binary.BigEndian.Uint16(resp[recordOffset+4 : recordOffset+6]))
				txChannelOffset := int(binary.BigEndian.Uint16(resp[recordOffset+10 : recordOffset+12]))
				txDeviceName := extractNullTerminatedString(resp, txDeviceOffset)
				txChannelName := extractNullTerminatedString(resp, txChannelOffset)

				if t.DebugDante {
					log.Printf("[dante] %s: multicast record %d: rx=%d txDevOffset=%d txDev=%q txChOffset=%d txCh=%q", ip, idx, rxChannelNum, txDeviceOffset, txDeviceName, txChannelOffset, txChannelName)
				}

				subscriptions = append(subscriptions, DanteSubscription{
					RxChannel:     rxChannelNum,
					TxDeviceName:  txDeviceName,
					TxChannelName: txChannelName,
					ChannelType:   DanteChannelAudio,
				})

				recordOffset += 20
			}
		} else {
			recordOffset := 14
			for idx := 0; idx < subCount; idx++ {
				if recordOffset+10 > len(resp) {
					break
				}

				rxChannelNum := idx + 1
				txChannelOffset := int(binary.BigEndian.Uint16(resp[recordOffset+4 : recordOffset+6]))
				txDeviceOffset := int(binary.BigEndian.Uint16(resp[recordOffset+6 : recordOffset+8]))

				txChannelName := extractNullTerminatedString(resp, txChannelOffset)
				txDeviceName := extractNullTerminatedString(resp, txDeviceOffset)

				if txDeviceName != "" {
					subscriptions = append(subscriptions, DanteSubscription{
						RxChannel:     rxChannelNum,
						TxDeviceName:  txDeviceName,
						TxChannelName: txChannelName,
						ChannelType:   DanteChannelAudio,
					})
				}

				recordOffset += 10
			}
		}
	}

	return subscriptions, hasMulticast
}

func extractNullTerminatedString(data []byte, offset int) string {
	if offset <= 0 || offset >= len(data) {
		return ""
	}
	end := offset
	for end < len(data) && data[end] != 0 {
		end++
	}
	if end > offset {
		return string(data[offset:end])
	}
	return ""
}

func (t *Tendrils) queryDanteSubscriptions3400(conn *net.UDPConn, ip net.IP, rxCount int) []DanteSubscription {
	if t.DebugDante {
		log.Printf("[dante] %s: trying 0x3400 fallback, rxCount=%d", ip, rxCount)
	}
	var subscriptions []DanteSubscription

	pagesNeeded := (rxCount + 15) / 16
	startChannel := 1
	for page := 0; page < pagesNeeded; page++ {
		pageNum := page + 1
		args := make([]byte, 24)
		args[7] = 0x01
		if startChannel == 1 {
			binary.BigEndian.PutUint16(args[8:10], 0x0001)
		} else {
			binary.BigEndian.PutUint16(args[8:10], 0x0003)
		}
		binary.BigEndian.PutUint16(args[10:12], uint16(startChannel))
		resp := t.sendDanteCommand28(conn, ip, 0x3400, args)
		if resp == nil {
			continue
		}
		if len(resp) < 48 {
			continue
		}

		if t.DebugDante {
			log.Printf("[dante] %s: 0x3400 page %d: got %d bytes", ip, pageNum, len(resp))
		}

		status := binary.BigEndian.Uint16(resp[8:10])
		if status != 0x8112 && status != 0x0001 {
			continue
		}

		recordCount := 0
		for i := 18; i < 50 && i+1 < len(resp); i += 2 {
			offset := int(binary.BigEndian.Uint16(resp[i : i+2]))
			if offset == 0 {
				break
			}
			recordCount++
		}
		if t.DebugDante {
			log.Printf("[dante] %s: 0x3400 page %d: found %d records", ip, pageNum, recordCount)
		}

		for i := 0; i < recordCount; i++ {
			offsetPos := 18 + i*2
			if offsetPos+2 > len(resp) {
				break
			}
			rawOffset := int(binary.BigEndian.Uint16(resp[offsetPos : offsetPos+2]))
			if rawOffset+28 > len(resp) {
				continue
			}

			var channelType DanteChannelType
			var flowStatus DanteFlowStatus
			var txChOffset, txDevOffset int

			marker := binary.BigEndian.Uint16(resp[rawOffset : rawOffset+2])
			if marker == 0x141c {
				if rawOffset+50 > len(resp) {
					log.Printf("[ERROR] [dante] %s: 0x3400 record %d at 0x%04x: 0x141c record truncated (need %d, have %d)", ip, i, rawOffset, rawOffset+50, len(resp))
					continue
				}
				channelType = DanteChannelType(binary.BigEndian.Uint16(resp[rawOffset+14 : rawOffset+16]))
				if channelType == DanteChannelUnknown {
					channelType = DanteChannelAudio
				}
				txChOffset = int(binary.BigEndian.Uint16(resp[rawOffset+44 : rawOffset+46]))
				txDevOffset = int(binary.BigEndian.Uint16(resp[rawOffset+46 : rawOffset+48]))
				flowStatus = DanteFlowStatus(resp[rawOffset+49])
			} else if marker == 0x141a {
				if rawOffset+50 > len(resp) {
					log.Printf("[ERROR] [dante] %s: 0x3400 record %d at 0x%04x: 0x141a record truncated", ip, i, rawOffset)
					continue
				}
				channelType = DanteChannelVideo
				txChOffset = int(binary.BigEndian.Uint16(resp[rawOffset+44 : rawOffset+46]))
				txDevOffset = int(binary.BigEndian.Uint16(resp[rawOffset+46 : rawOffset+48]))
				flowStatus = DanteFlowStatus(resp[rawOffset+49])
			} else {
				log.Printf("[ERROR] [dante] %s: 0x3400 record %d at 0x%04x: unknown marker 0x%04x (bytes: %x)", ip, i, rawOffset, marker, resp[rawOffset:rawOffset+8])
				continue
			}

			if txChOffset == 0 && txDevOffset == 0 {
				continue
			}

			var txDeviceName, txChannelName string
			if txChOffset > 0 && txChOffset < len(resp) {
				txChannelName = extractNullTerminatedString(resp, txChOffset)
			}
			if txDevOffset > 0 && txDevOffset < len(resp) {
				txDeviceName = extractNullTerminatedString(resp, txDevOffset)
			}

			if txDeviceName == "" {
				continue
			}

			rxChannel := startChannel + i
			if t.DebugDante {
				log.Printf("[dante] %s: 0x3400 sub: rx=%d txDev=%q txCh=%q type=%s status=%s", ip, rxChannel, txDeviceName, txChannelName, channelType, flowStatus)
			}

			subscriptions = append(subscriptions, DanteSubscription{
				RxChannel:     rxChannel,
				TxDeviceName:  txDeviceName,
				TxChannelName: txChannelName,
				ChannelType:   channelType,
				FlowStatus:    flowStatus,
			})
		}

		startChannel += 16
	}

	return subscriptions
}

func (t *Tendrils) probeDanteDevice(ip net.IP) {
	t.probeDanteDeviceWithPort(ip, danteControlPort)
}

func (t *Tendrils) probeDanteDeviceWithPort(ip net.IP, port int) {
	info := t.queryDanteDeviceWithPort(ip, port)
	if info == nil {
		return
	}

	if info.RxChannelCount > 0 || info.TxChannelCount > 0 {
		if t.DebugDante {
			log.Printf("[dante] %s:%d: name=%q rx=%d tx=%d subs=%d",
				ip, port, info.Name, info.RxChannelCount, info.TxChannelCount, len(info.Subscriptions))
		}

		if info.Name != "" {
			t.nodes.Update(nil, nil, []net.IP{ip}, "", info.Name, "dante-control")
		}

		needIGMPFallback := info.HasMulticast && info.Name != ""
		for _, sub := range info.Subscriptions {
			if t.DebugDante {
				log.Printf("[dante] %s: subscription rx=%d -> %s@%s type=%s",
					ip, sub.RxChannel, sub.TxChannelName, sub.TxDeviceName, sub.ChannelType)
			}
			if sub.TxDeviceName != "" && info.Name != "" {
				txDeviceName := sub.TxDeviceName
				if txDeviceName == "." {
					txDeviceName = info.Name
				}
				channelInfo := ""
				if sub.TxChannelName != "" {
					typeStr := sub.ChannelType.String()
					if typeStr != "" {
						channelInfo = fmt.Sprintf("%s → %02d [%s]", sub.TxChannelName, sub.RxChannel, typeStr)
					} else {
						channelInfo = fmt.Sprintf("%s → %02d", sub.TxChannelName, sub.RxChannel)
					}
				}
				sourceNode := t.nodes.GetOrCreateByName(txDeviceName)
				subscriberNode := t.nodes.GetOrCreateByName(info.Name)
				t.nodes.UpdateDanteFlow(sourceNode, subscriberNode, channelInfo, sub.FlowStatus)
				needIGMPFallback = false
			}
		}

		if needIGMPFallback {
			groups := t.nodes.GetDanteMulticastGroups(ip)
			for _, groupIP := range groups {
				sourceNode := t.nodes.GetDanteTxDeviceInGroup(groupIP)
				if t.DebugDante {
					sourceName := ""
					if sourceNode != nil {
						sourceName = sourceNode.DisplayName()
					}
					log.Printf("[dante] %s: multicast group %s -> tx device %q", ip, groupIP, sourceName)
				}
				if sourceNode == nil {
					sourceNode = t.nodes.GetOrCreateByName(multicastGroupName(groupIP))
				}
				subscriberNode := t.nodes.GetOrCreateByName(info.Name)
				t.nodes.UpdateDanteFlow(sourceNode, subscriberNode, "", DanteFlowActive)
			}
		}
	}
}
