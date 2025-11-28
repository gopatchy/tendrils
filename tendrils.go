package tendrils

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Tendrils struct {
	goroutines map[string]context.CancelFunc
}

func New() *Tendrils {
	return &Tendrils{
		goroutines: map[string]context.CancelFunc{},
	}
}

func (t *Tendrils) Run() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		interfaces := t.listInterfaces()
		t.updateGoroutines(interfaces)
		<-ticker.C
	}
}

func (t *Tendrils) listInterfaces() []net.Interface {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("[ERROR] error getting interfaces: %v", err)
		return nil
	}

	var validInterfaces []net.Interface
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		if iface.Flags&net.FlagBroadcast == 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}

		validInterfaces = append(validInterfaces, iface)
	}

	return validInterfaces
}

func (t *Tendrils) updateGoroutines(interfaces []net.Interface) {
	current := map[string]bool{}
	for _, iface := range interfaces {
		current[iface.Name] = true
	}

	for name, cancel := range t.goroutines {
		if !current[name] {
			log.Printf("interface removed: %s", name)
			cancel()
			delete(t.goroutines, name)
		}
	}

	for _, iface := range interfaces {
		if _, exists := t.goroutines[iface.Name]; !exists {
			log.Printf("interface added: %s", iface.Name)
			ctx, cancel := context.WithCancel(context.Background())
			t.goroutines[iface.Name] = cancel
			go t.handleInterface(ctx, iface)
		}
	}
}

func (t *Tendrils) handleInterface(ctx context.Context, iface net.Interface) {
	handle, err := pcap.OpenLive(iface.Name, 65536, true, 5*time.Second)
	if err != nil {
		log.Printf("[ERROR] failed to open interface %s: %v", iface.Name, err)
		return
	}
	defer handle.Close()

	bpfFilter := fmt.Sprintf("ether proto 0x88cc")
	if err := handle.SetBPFFilter(bpfFilter); err != nil {
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
