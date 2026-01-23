package tendrils

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func (t *Tendrils) listenIGMP(ctx context.Context, iface net.Interface) {
	handle, err := pcap.OpenLive(iface.Name, 65536, true, 5*time.Second)
	if err != nil {
		log.Printf("[ERROR] failed to open interface %s for igmp: %v", iface.Name, err)
		return
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("igmp"); err != nil {
		log.Printf("[ERROR] failed to set igmp filter on %s: %v", iface.Name, err)
		return
	}

	go t.runIGMPQuerier(ctx, iface)

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
			t.handleIGMPPacket(iface.Name, packet)
		}
	}
}

func (t *Tendrils) handleIGMPPacket(ifaceName string, packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip := ipLayer.(*layers.IPv4)
	sourceIP := ip.SrcIP

	igmpLayer := packet.Layer(layers.LayerTypeIGMP)
	if igmpLayer == nil {
		return
	}

	switch igmp := igmpLayer.(type) {
	case *layers.IGMPv1or2:
		t.handleIGMPv1or2(ifaceName, sourceIP, igmp)
	case *layers.IGMP:
		t.handleIGMPv3(ifaceName, sourceIP, igmp)
	}
}

func (t *Tendrils) handleIGMPv1or2(ifaceName string, sourceIP net.IP, igmp *layers.IGMPv1or2) {
	switch igmp.Type {
	case layers.IGMPMembershipReportV1, layers.IGMPMembershipReportV2:
		groupIP := igmp.GroupAddress
		if !groupIP.IsMulticast() || groupIP.IsLinkLocalMulticast() {
			return
		}
		if t.DebugIGMP {
			log.Printf("[igmp] %s: join %s -> %s", ifaceName, sourceIP, groupIP)
		}
		t.nodes.UpdateMulticastMembership(sourceIP, groupIP)

	case layers.IGMPLeaveGroup:
		groupIP := igmp.GroupAddress
		if t.DebugIGMP {
			log.Printf("[igmp] %s: leave %s -> %s", ifaceName, sourceIP, groupIP)
		}
		t.nodes.RemoveMulticastMembership(sourceIP, groupIP)
	}
}

func (t *Tendrils) handleIGMPv3(ifaceName string, sourceIP net.IP, igmp *layers.IGMP) {
	if igmp.Type != layers.IGMPMembershipReportV3 {
		return
	}

	for _, record := range igmp.GroupRecords {
		groupIP := record.MulticastAddress
		if !groupIP.IsMulticast() || groupIP.IsLinkLocalMulticast() {
			continue
		}

		switch record.Type {
		case layers.IGMPIsEx, layers.IGMPToEx, layers.IGMPIsIn, layers.IGMPToIn:
			if t.DebugIGMP {
				log.Printf("[igmp] %s: v3 join %s -> %s", ifaceName, sourceIP, groupIP)
			}
			t.nodes.UpdateMulticastMembership(sourceIP, groupIP)
		case layers.IGMPBlock:
			if t.DebugIGMP {
				log.Printf("[igmp] %s: v3 leave %s -> %s", ifaceName, sourceIP, groupIP)
			}
			t.nodes.RemoveMulticastMembership(sourceIP, groupIP)
		}
	}
}

func (t *Tendrils) runIGMPQuerier(ctx context.Context, iface net.Interface) {
	addrs, err := iface.Addrs()
	if err != nil {
		return
	}

	var srcIP net.IP
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			srcIP = ipnet.IP.To4()
			break
		}
	}
	if srcIP == nil {
		return
	}

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	t.sendIGMPQuery(iface.Name, srcIP)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.sendIGMPQuery(iface.Name, srcIP)
		}
	}
}

func (t *Tendrils) sendIGMPQuery(ifaceName string, srcIP net.IP) {
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return
	}
	defer handle.Close()

	eth := &layers.Ethernet{
		SrcMAC:       t.getInterfaceMAC(ifaceName),
		DstMAC:       net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      6,
		TTL:      1,
		Protocol: layers.IPProtocolIGMP,
		SrcIP:    srcIP,
		DstIP:    net.IPv4(224, 0, 0, 1),
		Options:  []layers.IPv4Option{{OptionType: 148, OptionLength: 4, OptionData: []byte{0, 0}}},
	}

	igmpPayload := buildIGMPQuery()

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

	if err := gopacket.SerializeLayers(buf, opts, eth, ip, gopacket.Payload(igmpPayload)); err != nil {
		if t.DebugIGMP {
			log.Printf("[igmp] %s: failed to serialize query: %v", ifaceName, err)
		}
		return
	}

	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		if t.DebugIGMP {
			log.Printf("[igmp] %s: failed to send query: %v", ifaceName, err)
		}
		return
	}

	if t.DebugIGMP {
		log.Printf("[igmp] %s: sent general query", ifaceName)
	}
}

func buildIGMPQuery() []byte {
	data := make([]byte, 8)
	data[0] = 0x11
	data[1] = 100
	data[4] = 0
	data[5] = 0
	data[6] = 0
	data[7] = 0

	checksum := igmpChecksum(data)
	data[2] = byte(checksum >> 8)
	data[3] = byte(checksum)

	return data
}

func igmpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (t *Tendrils) getInterfaceMAC(ifaceName string) net.HardwareAddr {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return net.HardwareAddr{0, 0, 0, 0, 0, 0}
	}
	return iface.HardwareAddr
}
