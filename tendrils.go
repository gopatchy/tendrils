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

func getInterfaceIPv4(iface net.Interface) (srcIP, broadcast net.IP) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			srcIP = ipnet.IP.To4()
			mask := ipnet.Mask
			broadcast = make(net.IP, 4)
			for i := 0; i < 4; i++ {
				broadcast[i] = srcIP[i] | ^mask[i]
			}
			return srcIP, broadcast
		}
	}
	return nil, nil
}

type Tendrils struct {
	activeInterfaces map[string]context.CancelFunc
	nodes            *Nodes
	artnet           *ArtNetNodes
	danteFlows       *DanteFlows

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
	DisableYamaha bool
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
	DebugYamaha   bool
	HTTPPort      string
}

func New() *Tendrils {
	t := &Tendrils{
		activeInterfaces: map[string]context.CancelFunc{},
		artnet:           NewArtNetNodes(),
		danteFlows:       NewDanteFlows(),
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
	t.startHTTPServer()

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

func (t *Tendrils) pollNode(node *Node) {
	t.nodes.mu.RLock()
	var ips []net.IP
	for _, iface := range node.Interfaces {
		for ipStr := range iface.IPs {
			ip := net.ParseIP(ipStr)
			if ip != nil && ip.To4() != nil {
				ips = append(ips, ip)
			}
		}
	}
	nodeName := node.DisplayName()
	t.nodes.mu.RUnlock()

	if !t.DisableSNMP {
		for _, ip := range ips {
			t.querySNMPDevice(node, ip)
		}
	}

	if !t.DisableBMD && nodeName == "" {
		for _, ip := range ips {
			t.probeBMDDevice(ip)
		}
	}

	if !t.DisableYamaha && nodeName == "" {
		for _, ip := range ips {
			t.probeYamahaDevice(ip)
		}
	}

	if !t.DisableDante {
		for _, ip := range ips {
			t.probeDanteDevice(ip)
		}
	}
}
