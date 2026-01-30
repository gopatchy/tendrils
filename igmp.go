package tendrils

import (
	"context"
	"log"
	"net"

	"github.com/gopatchy/multicast"
)

func (t *Tendrils) listenIGMP(ctx context.Context, iface net.Interface) {
	listener, err := multicast.NewListener(&iface,
		func(sourceIP, groupIP net.IP, join bool) {
			if join {
				t.nodes.UpdateMulticastMembership(sourceIP, groupIP)
			} else {
				t.nodes.RemoveMulticastMembership(sourceIP, groupIP)
			}
		})
	if err != nil {
		log.Printf("[ERROR] failed to create igmp listener on %s: %v", iface.Name, err)
		return
	}

	querier, err := multicast.NewQuerier(&iface)
	if err != nil {
		log.Printf("[ERROR] failed to create igmp querier on %s: %v", iface.Name, err)
	}
	if querier != nil {
		go querier.Run(ctx)
	}

	listener.Run(ctx)
}
