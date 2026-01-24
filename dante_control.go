package tendrils

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fvbommel/sortorder"
)

const (
	danteControlPort = 4440
)

var danteSeqID uint32

type DanteFlow struct {
	SourceName  string
	Subscribers map[string]*DanteFlowSubscriber
}

type DanteFlowSubscriber struct {
	Name        string
	Channels    []string
	LastSeen    time.Time
}

type DanteFlows struct {
	mu    sync.RWMutex
	flows map[string]*DanteFlow
}

func NewDanteFlows() *DanteFlows {
	return &DanteFlows{
		flows: map[string]*DanteFlow{},
	}
}

func (d *DanteFlows) Update(sourceName, subscriberName, channelInfo string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	flow := d.flows[sourceName]
	if flow == nil {
		flow = &DanteFlow{
			SourceName:  sourceName,
			Subscribers: map[string]*DanteFlowSubscriber{},
		}
		d.flows[sourceName] = flow
	}

	sub := flow.Subscribers[subscriberName]
	if sub == nil {
		sub = &DanteFlowSubscriber{
			Name: subscriberName,
		}
		flow.Subscribers[subscriberName] = sub
	}

	if channelInfo != "" {
		hasChannel := false
		for _, ch := range sub.Channels {
			if ch == channelInfo {
				hasChannel = true
				break
			}
		}
		if !hasChannel {
			sub.Channels = append(sub.Channels, channelInfo)
			sort.Strings(sub.Channels)
		}
	}

	sub.LastSeen = time.Now()
}

func (d *DanteFlows) Expire() {
	d.mu.Lock()
	defer d.mu.Unlock()

	expireTime := time.Now().Add(-5 * time.Minute)
	for sourceName, flow := range d.flows {
		for subName, sub := range flow.Subscribers {
			if sub.LastSeen.Before(expireTime) {
				delete(flow.Subscribers, subName)
			}
		}
		if len(flow.Subscribers) == 0 {
			delete(d.flows, sourceName)
		}
	}
}

func (d *DanteFlows) LogAll() {
	d.Expire()

	d.mu.RLock()
	defer d.mu.RUnlock()

	if len(d.flows) == 0 {
		return
	}

	var flows []*DanteFlow
	for _, flow := range d.flows {
		flows = append(flows, flow)
	}
	sort.Slice(flows, func(i, j int) bool {
		return sortorder.NaturalLess(flows[i].SourceName, flows[j].SourceName)
	})

	log.Printf("[sigusr1] ================ %d dante flows ================", len(flows))
	for _, flow := range flows {
		type channelFlow struct {
			txCh   string
			rxName string
			rxCh   string
		}
		var channelFlows []channelFlow
		var noChannelSubs []string

		for _, sub := range flow.Subscribers {
			if len(sub.Channels) == 0 {
				noChannelSubs = append(noChannelSubs, sub.Name)
			} else {
				for _, ch := range sub.Channels {
					parts := strings.Split(ch, "->")
					if len(parts) == 2 {
						channelFlows = append(channelFlows, channelFlow{
							txCh:   parts[0],
							rxName: sub.Name,
							rxCh:   parts[1],
						})
					} else {
						noChannelSubs = append(noChannelSubs, fmt.Sprintf("%s[%s]", sub.Name, ch))
					}
				}
			}
		}

		sort.Slice(channelFlows, func(i, j int) bool {
			if channelFlows[i].txCh != channelFlows[j].txCh {
				return sortorder.NaturalLess(channelFlows[i].txCh, channelFlows[j].txCh)
			}
			return sortorder.NaturalLess(channelFlows[i].rxName, channelFlows[j].rxName)
		})
		sort.Slice(noChannelSubs, func(i, j int) bool {
			return sortorder.NaturalLess(noChannelSubs[i], noChannelSubs[j])
		})

		sourceName := flow.SourceName
		if strings.HasPrefix(sourceName, "dante-av:") || strings.HasPrefix(sourceName, "dante-mcast:") {
			sourceName = "?? (" + sourceName + ")"
		}

		for _, cf := range channelFlows {
			log.Printf("[sigusr1]   %s[%s] -> %s[%s]", sourceName, cf.txCh, cf.rxName, cf.rxCh)
		}
		if len(noChannelSubs) > 0 {
			log.Printf("[sigusr1]   %s -> %s", sourceName, strings.Join(noChannelSubs, ", "))
		}
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
	}

	if info.TxChannelCount > 0 {
		t.queryDanteTxChannels(conn, ip, info.TxChannelCount)
		t.nodes.UpdateDanteTxChannels(info.Name, ip, fmt.Sprintf("%d", info.TxChannelCount))
	}

	return info
}

type DanteDeviceInfo struct {
	IP             net.IP
	Name           string
	RxChannelCount int
	TxChannelCount int
	Subscriptions  []DanteSubscription
	HasMulticast   bool
}

type DanteSubscription struct {
	RxChannel     int
	TxDeviceName  string
	TxChannelName string
}

func buildDantePacket(cmd uint16, args []byte) []byte {
	seq := nextDanteSeq()
	argLen := len(args)
	totalLen := 10 + argLen

	pkt := make([]byte, totalLen)
	pkt[0] = 0x27
	pkt[1] = byte(seq & 0xff)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], 0x1300|seq)
	binary.BigEndian.PutUint16(pkt[6:8], cmd)
	pkt[8] = 0x00
	pkt[9] = 0x00
	if argLen > 0 {
		copy(pkt[10:], args)
	}

	return pkt
}

func (t *Tendrils) sendDanteCommand(conn *net.UDPConn, ip net.IP, cmd uint16, args []byte) []byte {
	pkt := buildDantePacket(cmd, args)

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

func (t *Tendrils) queryDanteDeviceName(conn *net.UDPConn, ip net.IP) string {
	// 0x1003 returns device info - name position varies by device
	resp := t.sendDanteCommand(conn, ip, 0x1003, nil)
	if resp == nil || len(resp) < 40 {
		return ""
	}

	// Find the first printable string that looks like a device name
	// Look for patterns like "AJA-", "ULXD", etc starting from offset 40
	for i := 40; i < len(resp)-4; i++ {
		if resp[i] >= 'A' && resp[i] <= 'Z' {
			// Found uppercase letter, might be start of name
			end := i
			for end < len(resp) && resp[end] != 0 && resp[end] >= 0x20 && resp[end] < 0x7f {
				end++
			}
			if end-i >= 4 && end-i < 40 {
				name := string(resp[i:end])
				// Skip "Audinate" which is the platform name
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
				})

				recordOffset += 20
			}
		} else {
			recordOffset := 14
			for idx := 0; idx < subCount; idx++ {
				if recordOffset+10 > len(resp) {
					break
				}

				rxChannelNum := int(binary.BigEndian.Uint16(resp[recordOffset : recordOffset+2]))
				txChannelOffset := int(binary.BigEndian.Uint16(resp[recordOffset+4 : recordOffset+6]))
				txDeviceOffset := int(binary.BigEndian.Uint16(resp[recordOffset+6 : recordOffset+8]))

				txChannelName := extractNullTerminatedString(resp, txChannelOffset)
				txDeviceName := extractNullTerminatedString(resp, txDeviceOffset)


				if txDeviceName != "" {
					subscriptions = append(subscriptions, DanteSubscription{
						RxChannel:     rxChannelNum,
						TxDeviceName:  txDeviceName,
						TxChannelName: txChannelName,
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

		for _, sub := range info.Subscriptions {
			if t.DebugDante {
				log.Printf("[dante] %s: subscription rx=%d -> %s@%s",
					ip, sub.RxChannel, sub.TxChannelName, sub.TxDeviceName)
			}
			if sub.TxDeviceName != "" && info.Name != "" {
				channelInfo := ""
				if sub.TxChannelName != "" {
					channelInfo = fmt.Sprintf("%s->%d", sub.TxChannelName, sub.RxChannel)
				}
				t.danteFlows.Update(sub.TxDeviceName, info.Name, channelInfo)
			}
		}

		if info.HasMulticast && info.Name != "" {
			groups := t.nodes.GetDanteMulticastGroups(ip)
			for _, groupIP := range groups {
				sourceName := t.nodes.GetDanteTxDeviceInGroup(groupIP)
				if t.DebugDante {
					log.Printf("[dante] %s: multicast group %s -> tx device %q", ip, groupIP, sourceName)
				}
				if sourceName == "" {
					sourceName = (&MulticastGroup{IP: groupIP}).Name()
				}
				t.danteFlows.Update(sourceName, info.Name, "")
			}
		}
	}
}
