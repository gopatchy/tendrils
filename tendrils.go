package tendrils

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type Tendrils struct {
	activeInterfaces map[string]context.CancelFunc
	nodes            *Nodes
	artnet           *ArtNetNodes

	Interface     string
	DisableARP    bool
	DisableLLDP   bool
	DisableSNMP   bool
	DisableIGMP   bool
	DisableMDNS   bool
	DisableArtNet bool
	DisableDante  bool
	DisableBMD    bool
	DisableShure  bool
	LogEvents     bool
	LogNodes      bool
	DebugARP      bool
	DebugLLDP     bool
	DebugSNMP     bool
	DebugIGMP     bool
	DebugMDNS     bool
	DebugArtNet   bool
	DebugDante    bool
	DebugBMD      bool
	DebugShure    bool
}

func New() *Tendrils {
	t := &Tendrils{
		activeInterfaces: map[string]context.CancelFunc{},
		artnet:           NewArtNetNodes(),
	}
	t.nodes = NewNodes(t)
	return t
}

func (t *Tendrils) Run() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGUSR1)
	go func() {
		for range sigCh {
			t.nodes.LogAll()
		}
	}()

	t.populateLocalAddresses()

	if !t.DisableARP {
		t.readARPTable()
		go t.pollARP(ctx)
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		interfaces := t.listInterfaces()
		t.updateInterfaces(interfaces)
		<-ticker.C
	}
}

func (t *Tendrils) populateLocalAddresses() {
	interfaces, err := net.Interfaces()
	if err != nil {
		return
	}

	hostname, _ := os.Hostname()

	var target *Node
	for _, netIface := range interfaces {
		if len(netIface.HardwareAddr) == 0 {
			continue
		}

		var ips []net.IP
		addrs, err := netIface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok {
					if ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
						ips = append(ips, ipnet.IP)
					}
				}
			}
		}

		t.nodes.Update(target, netIface.HardwareAddr, ips, netIface.Name, hostname, "local")
		if target == nil {
			target = t.nodes.GetByMAC(netIface.HardwareAddr)
		}
	}
}

func (t *Tendrils) getLocalNode() *Node {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	for _, iface := range interfaces {
		if len(iface.HardwareAddr) > 0 {
			if node := t.nodes.GetByMAC(iface.HardwareAddr); node != nil {
				return node
			}
		}
	}
	return nil
}

func (t *Tendrils) listInterfaces() []net.Interface {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("[ERROR] error getting interfaces: %v", err)
		return nil
	}

	var validInterfaces []net.Interface
	for _, iface := range interfaces {
		if t.Interface != "" && iface.Name != t.Interface {
			continue
		}
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

func (t *Tendrils) updateInterfaces(interfaces []net.Interface) {
	current := map[string]bool{}
	for _, iface := range interfaces {
		current[iface.Name] = true
	}

	for name, cancel := range t.activeInterfaces {
		if !current[name] {
			log.Printf("[iface] remove: %s", name)
			cancel()
			delete(t.activeInterfaces, name)
		}
	}

	for _, iface := range interfaces {
		if _, exists := t.activeInterfaces[iface.Name]; !exists {
			log.Printf("[iface] add: %s", iface.Name)
			ctx, cancel := context.WithCancel(context.Background())
			t.activeInterfaces[iface.Name] = cancel
			t.startInterface(ctx, iface)
		}
	}
}

func (t *Tendrils) startInterface(ctx context.Context, iface net.Interface) {
	if !t.DisableLLDP {
		go t.listenLLDP(ctx, iface)
	}
	if !t.DisableIGMP {
		go t.listenIGMP(ctx, iface)
	}
	if !t.DisableMDNS {
		go t.listenMDNS(ctx, iface)
	}
	if !t.DisableArtNet {
		go t.listenArtNet(ctx, iface)
	}
	if !t.DisableDante {
		go t.listenDante(ctx, iface)
	}
	if !t.DisableBMD {
		go t.listenBMD(ctx, iface)
	}
	if !t.DisableShure {
		go t.listenShure(ctx, iface)
	}
}
