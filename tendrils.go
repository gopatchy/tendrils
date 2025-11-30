package tendrils

import (
	"context"
	"log"
	"net"
	"time"
)

type Tendrils struct {
	activeInterfaces map[string]context.CancelFunc
	nodes            *Nodes
}

func New() *Tendrils {
	return &Tendrils{
		activeInterfaces: map[string]context.CancelFunc{},
		nodes:            NewNodes(),
	}
}

func (t *Tendrils) Run() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go t.pollARP(ctx)
	go t.pollSNMP(ctx)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		interfaces := t.listInterfaces()
		t.updateInterfaces(interfaces)
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
	go t.listenLLDP(ctx, iface)
}
