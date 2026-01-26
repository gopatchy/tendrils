package tendrils

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type BroadcastSample struct {
	Time    time.Time
	Bucket  string
	Packets uint64
	Bytes   uint64
}

type BroadcastStats struct {
	mu            sync.RWMutex
	samples       []BroadcastSample
	totalPackets  uint64
	totalBytes    uint64
	windowSize    time.Duration
	lastNotify    time.Time
	notifyMinRate time.Duration
	t             *Tendrils
}

type BroadcastBucket struct {
	Name        string  `json:"name"`
	PacketsPerS float64 `json:"packets_per_s"`
	BytesPerS   float64 `json:"bytes_per_s"`
}

type BroadcastStatsResponse struct {
	TotalPackets uint64             `json:"total_packets"`
	TotalBytes   uint64             `json:"total_bytes"`
	PacketsPerS  float64            `json:"packets_per_s"`
	BytesPerS    float64            `json:"bytes_per_s"`
	WindowSecs   float64            `json:"window_secs"`
	Buckets      []*BroadcastBucket `json:"buckets,omitempty"`
}

func NewBroadcastStats(t *Tendrils) *BroadcastStats {
	return &BroadcastStats{
		samples:       []BroadcastSample{},
		windowSize:    60 * time.Second,
		notifyMinRate: 1 * time.Second,
		t:             t,
	}
}

func (b *BroadcastStats) Record(bucket string, packets, bytes uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	b.samples = append(b.samples, BroadcastSample{
		Time:    now,
		Bucket:  bucket,
		Packets: packets,
		Bytes:   bytes,
	})
	b.totalPackets += packets
	b.totalBytes += bytes

	cutoff := now.Add(-b.windowSize)
	for len(b.samples) > 0 && b.samples[0].Time.Before(cutoff) {
		b.samples = b.samples[1:]
	}

	if now.Sub(b.lastNotify) >= b.notifyMinRate {
		b.lastNotify = now
		b.t.NotifyUpdate()
	}
}

func (b *BroadcastStats) GetStats() BroadcastStatsResponse {
	b.mu.RLock()
	defer b.mu.RUnlock()

	now := time.Now()
	cutoff := now.Add(-b.windowSize)

	var windowPackets, windowBytes uint64
	var oldestTime time.Time
	bucketPackets := map[string]uint64{}
	bucketBytes := map[string]uint64{}

	for _, s := range b.samples {
		if s.Time.After(cutoff) {
			if oldestTime.IsZero() || s.Time.Before(oldestTime) {
				oldestTime = s.Time
			}
			windowPackets += s.Packets
			windowBytes += s.Bytes
			bucketPackets[s.Bucket] += s.Packets
			bucketBytes[s.Bucket] += s.Bytes
		}
	}

	var windowSecs float64
	if !oldestTime.IsZero() {
		windowSecs = now.Sub(oldestTime).Seconds()
	}
	if windowSecs < 1 {
		windowSecs = 1
	}

	var buckets []*BroadcastBucket
	for name := range bucketPackets {
		buckets = append(buckets, &BroadcastBucket{
			Name:        name,
			PacketsPerS: float64(bucketPackets[name]) / windowSecs,
			BytesPerS:   float64(bucketBytes[name]) / windowSecs,
		})
	}
	sort.Slice(buckets, func(i, j int) bool {
		return buckets[i].PacketsPerS > buckets[j].PacketsPerS
	})

	return BroadcastStatsResponse{
		TotalPackets: b.totalPackets,
		TotalBytes:   b.totalBytes,
		PacketsPerS:  float64(windowPackets) / windowSecs,
		BytesPerS:    float64(windowBytes) / windowSecs,
		WindowSecs:   windowSecs,
		Buckets:      buckets,
	}
}

func (t *Tendrils) listenBroadcast(ctx context.Context, iface net.Interface) {
	handle, err := pcap.OpenLive(iface.Name, 65536, true, 5*time.Second)
	if err != nil {
		log.Printf("[ERROR] broadcast: failed to open interface %s: %v", iface.Name, err)
		return
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("ether broadcast"); err != nil {
		log.Printf("[ERROR] broadcast: failed to set BPF filter on %s: %v", iface.Name, err)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-packets:
			if !ok {
				return
			}
			t.handleBroadcastPacket(packet)
		}
	}
}

func (t *Tendrils) handleBroadcastPacket(packet gopacket.Packet) {
	if t.broadcast == nil {
		return
	}

	packetLen := uint64(len(packet.Data()))
	bucket := classifyBroadcastPacket(packet)
	t.broadcast.Record(bucket, 1, packetLen)

	if t.DebugBroadcast {
		log.Printf("[broadcast] %s: %d bytes", bucket, packetLen)
	}
}

func classifyBroadcastPacket(packet gopacket.Packet) string {
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		return "ARP"
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		port := uint16(udp.DstPort)
		switch port {
		case 67, 68:
			return "DHCP"
		case 137:
			return "NetBIOS-NS"
		case 138:
			return "NetBIOS-DG"
		case 5353:
			return "mDNS"
		case 1900:
			return "SSDP"
		case 3702:
			return "WS-Discovery"
		default:
			return fmt.Sprintf("UDP/%d", port)
		}
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		return fmt.Sprintf("TCP/%d", tcp.DstPort)
	}

	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		return "ICMP"
	}

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer != nil {
		eth := ethLayer.(*layers.Ethernet)
		return fmt.Sprintf("0x%04x", uint16(eth.EthernetType))
	}

	return "other"
}

func (t *Tendrils) pingBroadcast(ctx context.Context, iface net.Interface) {
	_, broadcast := getInterfaceIPv4(iface)
	if broadcast == nil {
		return
	}

	t.sendBroadcastPing(broadcast, iface.Name)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.sendBroadcastPing(broadcast, iface.Name)
		}
	}
}

func (t *Tendrils) sendBroadcastPing(broadcast net.IP, ifaceName string) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		if t.DebugARP {
			log.Printf("[broadcast] %s: failed to create icmp socket: %v", ifaceName, err)
		}
		return
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   1,
			Seq:  1,
			Data: []byte("tendrils"),
		},
	}
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return
	}

	_, err = conn.WriteTo(msgBytes, &net.IPAddr{IP: broadcast})
	if err != nil {
		if t.DebugARP {
			log.Printf("[broadcast] %s: failed to send ping to %s: %v", ifaceName, broadcast, err)
		}
		return
	}

	if t.DebugARP {
		log.Printf("[broadcast] %s: sent ping to %s", ifaceName, broadcast)
	}
}
