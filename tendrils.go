package tendrils

import (
	"context"
	"log"
	"net"
	"os"
	"time"
)

type Tendrils struct {
	activeInterfaces map[string]context.CancelFunc
	nodes            *Nodes

	Interface   string
	DisableARP  bool
	DisableLLDP bool
	DisableSNMP bool
	LogEvents   bool
	DebugARP    bool
	DebugLLDP   bool
	DebugSNMP   bool
}

func New() *Tendrils {
	t := &Tendrils{
		activeInterfaces: map[string]context.CancelFunc{},
	}
	t.nodes = NewNodes(t)
	return t
}

func (t *Tendrils) Run() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.populateLocalAddresses()

	if !t.DisableARP {
		go t.pollARP(ctx)
	}
	if !t.DisableSNMP {
		go t.pollSNMP(ctx)
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

	t.nodes.mu.Lock()
	defer t.nodes.mu.Unlock()

	root := t.nodes.nodes[0]

	hostname, err := os.Hostname()
	if err == nil {
		root.Name = hostname
	}

	for _, netIface := range interfaces {
		if len(netIface.HardwareAddr) == 0 {
			continue
		}

		macKey := netIface.HardwareAddr.String()
		iface := &Interface{
			Name: netIface.Name,
			MAC:  netIface.HardwareAddr,
			IPs:  map[string]net.IP{},
		}

		addrs, err := netIface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok {
					if ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
						ipKey := ipnet.IP.String()
						iface.IPs[ipKey] = ipnet.IP
						t.nodes.ipIndex[ipKey] = 0
					}
				}
			}
		}

		root.Interfaces[macKey] = iface
		t.nodes.macIndex[macKey] = 0
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
			log.Printf("interface removed: %s", name)
			cancel()
			delete(t.activeInterfaces, name)
		}
	}

	for _, iface := range interfaces {
		if _, exists := t.activeInterfaces[iface.Name]; !exists {
			log.Printf("interface added: %s", iface.Name)
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
}
