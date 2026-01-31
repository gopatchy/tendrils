package tendrils

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

type artmapConfig struct {
	Targets  []artmapTarget  `json:"targets"`
	Mappings []artmapMapping `json:"mappings"`
	Senders  []artmapSender  `json:"senders"`
}

type artmapSender struct {
	Universe artmapUniverse `json:"universe"`
	IP       string         `json:"ip"`
}

type artmapTarget struct {
	Universe artmapUniverse `json:"universe"`
	Address  string         `json:"address"`
}

type artmapMapping struct {
	From artmapFromAddr `json:"from"`
	To   artmapToAddr   `json:"to"`
}

type artmapUniverse struct {
	Protocol string `json:"protocol"`
	Number   uint16 `json:"number"`
}

type artmapFromAddr struct {
	Universe     artmapUniverse `json:"universe"`
	ChannelStart int            `json:"channel_start"`
	ChannelEnd   int            `json:"channel_end"`
}

type artmapToAddr struct {
	Universe     artmapUniverse `json:"universe"`
	ChannelStart int            `json:"channel_start"`
}

var artmapClient = &http.Client{Timeout: 2 * time.Second}

func (t *Tendrils) probeArtmap(ip net.IP) {
	url := fmt.Sprintf("http://%s:8080/artmap/api/status", ip)

	resp, err := artmapClient.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.Header.Get("Server") != "artmap" {
		return
	}

	var cfg artmapConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		if t.DebugArtmap {
			log.Printf("[artmap] decode error ip=%s: %v", ip, err)
		}
		return
	}

	if t.DebugArtmap {
		log.Printf("[artmap] found ip=%s targets=%d mappings=%d", ip, len(cfg.Targets), len(cfg.Mappings))
	}

	artmapNode := t.nodes.GetByIP(ip)
	t.processArtmapConfig(&cfg, artmapNode)
}

func (t *Tendrils) processArtmapConfig(cfg *artmapConfig, artmapNode *Node) {
	updated := false

	if artmapNode != nil && len(cfg.Mappings) > 0 {
		mappings := make([]ArtmapMapping, len(cfg.Mappings))
		for i, m := range cfg.Mappings {
			mappings[i] = ArtmapMapping{
				From: formatArtmapAddr(m.From),
				To:   formatArtmapToAddr(m.To),
			}
		}
		t.nodes.UpdateArtmapMappings(artmapNode, mappings)
		updated = true
	}

	// Targets are destinations that receive ArtNet/sACN from artmap.
	// They have artnet_outputs (output to DMX, input from network).
	for _, target := range cfg.Targets {
		ip := parseTargetIP(target.Address)
		if ip == nil {
			continue
		}

		node := t.nodes.Update(nil, nil, []net.IP{ip}, "", "", "artmap")

		universe := int(target.Universe.Number)
		switch target.Universe.Protocol {
		case "artnet":
			t.nodes.UpdateArtNet(node, nil, []int{universe})
			if t.DebugArtmap {
				log.Printf("[artmap] marked %s (%s) as artnet output for universe %d", node.DisplayName(), ip, universe)
			}
		case "sacn":
			t.nodes.UpdateSACNUnicastInputs(node, []int{universe})
			if t.DebugArtmap {
				log.Printf("[artmap] marked %s (%s) as sacn input for universe %d", node.DisplayName(), ip, universe)
			}
		default:
			continue
		}
		updated = true
	}

	// Senders are sources that send ArtNet/sACN to artmap.
	// They have artnet_inputs (input from DMX, output to network).
	for _, sender := range cfg.Senders {
		ip := net.ParseIP(sender.IP)
		if ip == nil {
			continue
		}

		node := t.nodes.Update(nil, nil, []net.IP{ip}, "", "", "artmap")

		universe := int(sender.Universe.Number)
		switch sender.Universe.Protocol {
		case "artnet":
			t.nodes.UpdateArtNet(node, []int{universe}, nil)
			if t.DebugArtmap {
				log.Printf("[artmap] marked %s (%s) as artnet input for universe %d", node.DisplayName(), ip, universe)
			}
		case "sacn":
			t.nodes.UpdateSACN(node, []int{universe})
			if t.DebugArtmap {
				log.Printf("[artmap] marked %s (%s) as sacn output for universe %d", node.DisplayName(), ip, universe)
			}
		default:
			continue
		}
		updated = true
	}

	if updated {
		t.NotifyUpdate()
	}
}

func parseTargetIP(addr string) net.IP {
	host := addr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		h, _, err := net.SplitHostPort(addr)
		if err == nil {
			host = h
		}
	}
	return net.ParseIP(host)
}

func formatArtmapAddr(a artmapFromAddr) string {
	u := formatArtmapUniverse(a.Universe)
	if a.ChannelStart == 1 && a.ChannelEnd == 512 {
		return u
	}
	if a.ChannelStart == a.ChannelEnd {
		return fmt.Sprintf("%s:%d", u, a.ChannelStart)
	}
	return fmt.Sprintf("%s:%d-%d", u, a.ChannelStart, a.ChannelEnd)
}

func formatArtmapToAddr(a artmapToAddr) string {
	u := formatArtmapUniverse(a.Universe)
	if a.ChannelStart == 1 {
		return u
	}
	return fmt.Sprintf("%s:%d", u, a.ChannelStart)
}

func formatArtmapUniverse(u artmapUniverse) string {
	return fmt.Sprintf("%s:%d", u.Protocol, u.Number)
}

func (n *Nodes) UpdateArtmapMappings(node *Node, mappings []ArtmapMapping) {
	n.mu.Lock()
	defer n.mu.Unlock()
	node.ArtmapMappings = mappings
}
