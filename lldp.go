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

	if len(lldp.ChassisID.ID) == 6 {
		mac := net.HardwareAddr(lldp.ChassisID.ID)
		if !isBroadcastOrZero(mac) {
			childPort := string(lldp.PortID.ID)

			var systemName string
			for _, opt := range lldp.Values {
				if opt.Type == layers.LLDPTLVSysName {
					systemName = string(opt.Value)
					break
				}
			}

			t.nodes.Update(nil, []net.HardwareAddr{mac}, ifaceName, childPort, "lldp")

			if systemName != "" {
				t.nodes.SetName(mac, systemName)
			}
		}
	}
}

func isBroadcastOrZero(mac net.HardwareAddr) bool {
	if len(mac) != 6 {
		return true
	}

	allZero := true
	allFF := true

	for _, b := range mac {
		if b != 0x00 {
			allZero = false
		}
		if b != 0xff {
			allFF = false
		}
	}

	if allZero || allFF {
		return true
	}

	if mac[0] == 0x01 && mac[1] == 0x00 && mac[2] == 0x5e {
		return true
	}

	if mac[0] == 0x33 && mac[1] == 0x33 {
		return true
	}

	return false
}
