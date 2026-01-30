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
	url := fmt.Sprintf("http://%s:8080/api/config", ip)

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

	t.processArtmapConfig(&cfg)
}

func (t *Tendrils) processArtmapConfig(cfg *artmapConfig) {
	updated := false
	for _, target := range cfg.Targets {
		ip := parseTargetIP(target.Address)
		if ip == nil {
			continue
		}

		node := t.nodes.GetByIP(ip)
		if node == nil {
			continue
		}

		universe := int(target.Universe.Number)
		switch target.Universe.Protocol {
		case "artnet":
			t.nodes.UpdateArtNet(node, []int{universe}, nil)
			if t.DebugArtmap {
				log.Printf("[artmap] marked %s (%s) as artnet input for universe %d", node.DisplayName(), ip, universe)
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
