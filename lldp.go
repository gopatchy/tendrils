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

func (t *Tendrils) listenLLDP(ctx context.Context, iface net.Interface) {
	handle, err := pcap.OpenLive(iface.Name, 65536, true, 5*time.Second)
	if err != nil {
		log.Printf("[ERROR] failed to open interface %s: %v", iface.Name, err)
		return
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("ether proto 0x88cc"); err != nil {
		log.Printf("[ERROR] failed to set BPF filter on %s: %v", iface.Name, err)
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
			t.handleLLDPPacket(iface.Name, packet)
		}
	}
}

func (t *Tendrils) handleLLDPPacket(ifaceName string, packet gopacket.Packet) {
	lldpLayer := packet.Layer(layers.LayerTypeLinkLayerDiscovery)
	if lldpLayer == nil {
		return
	}

	lldp, ok := lldpLayer.(*layers.LinkLayerDiscovery)
	if !ok {
		return
	}

	log.Printf("[%s] lldp packet received: ChassisID=%x PortID=%s TTL=%d",
		ifaceName, lldp.ChassisID.ID, lldp.PortID.ID, lldp.TTL)
}
