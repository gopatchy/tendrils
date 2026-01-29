package tendrils

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"github.com/gopatchy/sacn"
)

type SACNSource struct {
	CID        string
	SourceName string
	Universes  []int
	SrcIP      net.IP
	LastSeen   time.Time
}

type SACNSources struct {
	mu      sync.RWMutex
	sources map[string]*SACNSource
}

func NewSACNSources() *SACNSources {
	return &SACNSources{
		sources: map[string]*SACNSource{},
	}
}

func (s *SACNSources) Update(cid [16]byte, sourceName string, universes []uint16, srcIP net.IP) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cidStr := sacn.FormatCID(cid)
	intUniverses := make([]int, len(universes))
	for i, u := range universes {
		intUniverses[i] = int(u)
	}

	existing, exists := s.sources[cidStr]
	if exists {
		existing.SourceName = sourceName
		existing.Universes = intUniverses
		existing.SrcIP = srcIP
		existing.LastSeen = time.Now()
	} else {
		s.sources[cidStr] = &SACNSource{
			CID:        cidStr,
			SourceName: sourceName,
			Universes:  intUniverses,
			SrcIP:      srcIP,
			LastSeen:   time.Now(),
		}
	}
}

func (s *SACNSources) Expire() {
	s.mu.Lock()
	defer s.mu.Unlock()

	expireTime := time.Now().Add(-60 * time.Second)
	for cid, source := range s.sources {
		if source.LastSeen.Before(expireTime) {
			delete(s.sources, cid)
		}
	}
}

func (t *Tendrils) startSACNDiscoveryListener(ctx context.Context, iface net.Interface) {
	receiver, err := sacn.NewReceiver("")
	if err != nil {
		log.Printf("[ERROR] failed to create sacn receiver: %v", err)
		return
	}
	defer receiver.Stop()

	if err := receiver.JoinDiscovery(&iface); err != nil {
		log.Printf("[ERROR] failed to join sacn discovery multicast on %s: %v", iface.Name, err)
		return
	}

	if t.DebugSACN {
		log.Printf("[sacn] listening for discovery on %s", iface.Name)
	}

	receiver.SetHandler(func(src *net.UDPAddr, pkt interface{}) {
		if disc, ok := pkt.(*sacn.DiscoveryPacket); ok {
			t.handleSACNDiscoveryPacket(src.IP, disc)
		}
	})

	receiver.Start()
	<-ctx.Done()
}

func (t *Tendrils) handleSACNDiscoveryPacket(srcIP net.IP, pkt *sacn.DiscoveryPacket) {
	if t.DebugSACN {
		log.Printf("[sacn] discovery from %q cid=%s ip=%s universes=%v", pkt.SourceName, sacn.FormatCID(pkt.CID), srcIP, pkt.Universes)
	}

	if srcIP != nil && pkt.SourceName != "" {
		t.nodes.Update(nil, nil, []net.IP{srcIP}, "", pkt.SourceName, "sacn")
	}

	t.sacnSources.Update(pkt.CID, pkt.SourceName, pkt.Universes, srcIP)
	t.NotifyUpdate()
}
