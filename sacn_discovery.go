package tendrils

import (
	"context"
	"encoding/binary"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fvbommel/sortorder"
	"golang.org/x/net/ipv4"
)

const (
	sacnPort                    = 5568
	vectorRootE131Extended      = 0x00000008
	vectorE131Discovery         = 0x00000002
	vectorUniverseDiscovery     = 0x00000001
)

var sacnDiscoveryAddr = net.IPv4(239, 255, 250, 214)

var sacnPacketIdentifier = [12]byte{
	0x41, 0x53, 0x43, 0x2d, 0x45, 0x31, 0x2e, 0x31, 0x37, 0x00, 0x00, 0x00,
}

type SACNSource struct {
	TypeID     string    `json:"typeid"`
	Node       *Node     `json:"node"`
	SourceName string    `json:"source_name"`
	CID        string    `json:"cid"`
	Universes  []int     `json:"universes"`
	LastSeen   time.Time `json:"last_seen"`
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

func (s *SACNSources) Update(cid [16]byte, sourceName string, universes []int, srcIP net.IP) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cidStr := formatCID(cid)
	existing, exists := s.sources[cidStr]
	if exists {
		existing.SourceName = sourceName
		existing.Universes = universes
		existing.LastSeen = time.Now()
	} else {
		s.sources[cidStr] = &SACNSource{
			TypeID:     newTypeID("sacnsource"),
			SourceName: sourceName,
			CID:        cidStr,
			Universes:  universes,
			LastSeen:   time.Now(),
		}
	}
}

func (s *SACNSources) SetNode(cid string, node *Node) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if source, exists := s.sources[cid]; exists {
		source.Node = node
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

func (s *SACNSources) GetAll() []*SACNSource {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*SACNSource, 0, len(s.sources))
	for _, source := range s.sources {
		result = append(result, source)
	}
	return result
}

func formatCID(cid [16]byte) string {
	return strings.ToLower(formatUUID(cid))
}

func formatUUID(b [16]byte) string {
	return strings.ToUpper(
		strings.Join([]string{
			encodeHex(b[0:4]),
			encodeHex(b[4:6]),
			encodeHex(b[6:8]),
			encodeHex(b[8:10]),
			encodeHex(b[10:16]),
		}, "-"),
	)
}

func encodeHex(b []byte) string {
	const hexChars = "0123456789ABCDEF"
	result := make([]byte, len(b)*2)
	for i, v := range b {
		result[i*2] = hexChars[v>>4]
		result[i*2+1] = hexChars[v&0x0f]
	}
	return string(result)
}

func (t *Tendrils) startSACNDiscoveryListener(ctx context.Context, iface net.Interface) {
	c, err := net.ListenPacket("udp4", ":5568")
	if err != nil {
		log.Printf("[ERROR] failed to listen sacn discovery: %v", err)
		return
	}
	defer c.Close()

	p := ipv4.NewPacketConn(c)

	if err := p.JoinGroup(&iface, &net.UDPAddr{IP: sacnDiscoveryAddr}); err != nil {
		log.Printf("[ERROR] failed to join sacn discovery multicast on %s: %v", iface.Name, err)
		return
	}

	if t.DebugSACN {
		log.Printf("[sacn] listening for discovery on %s", iface.Name)
	}

	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		c.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			continue
		}

		t.handleSACNDiscoveryPacket(buf[:n])
	}
}

func (t *Tendrils) handleSACNDiscoveryPacket(data []byte) {
	if len(data) < 120 {
		return
	}

	if data[4] != sacnPacketIdentifier[0] || data[5] != sacnPacketIdentifier[1] ||
		data[6] != sacnPacketIdentifier[2] || data[7] != sacnPacketIdentifier[3] {
		return
	}

	rootVector := binary.BigEndian.Uint32(data[18:22])
	if rootVector != vectorRootE131Extended {
		return
	}

	framingVector := binary.BigEndian.Uint32(data[40:44])
	if framingVector != vectorE131Discovery {
		return
	}

	var cid [16]byte
	copy(cid[:], data[22:38])

	sourceName := strings.TrimRight(string(data[44:108]), "\x00")

	discoveryVector := binary.BigEndian.Uint32(data[114:118])
	if discoveryVector != vectorUniverseDiscovery {
		return
	}

	universeCount := (len(data) - 120) / 2
	universes := make([]int, 0, universeCount)
	for i := 0; i < universeCount; i++ {
		u := binary.BigEndian.Uint16(data[120+i*2 : 122+i*2])
		if u >= 1 && u <= 63999 {
			universes = append(universes, int(u))
		}
	}

	if t.DebugSACN {
		log.Printf("[sacn] discovery from %q cid=%s universes=%v", sourceName, formatCID(cid), universes)
	}

	t.sacnSources.Update(cid, sourceName, universes, nil)
	t.NotifyUpdate()
}

func (t *Tendrils) getSACNSources() []*SACNSource {
	t.sacnSources.Expire()

	sources := t.sacnSources.GetAll()
	sort.Slice(sources, func(i, j int) bool {
		return sortorder.NaturalLess(sources[i].SourceName, sources[j].SourceName)
	})

	return sources
}
