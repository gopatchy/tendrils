package tendrils

import (
	"context"
	"log"
	"net"
	"time"
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
	<-ctx.Done()
}
