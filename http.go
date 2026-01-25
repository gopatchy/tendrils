package tendrils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/fvbommel/sortorder"
)

const (
	certFile = "cert.pem"
	keyFile  = "key.pem"
)

type StatusResponse struct {
	Nodes           []*Node                  `json:"nodes"`
	Links           []*Link                  `json:"links"`
	MulticastGroups []*MulticastGroupMembers `json:"multicast_groups"`
	ArtNetNodes     []*ArtNetNode            `json:"artnet_nodes"`
	DanteFlows      []*DanteFlow             `json:"dante_flows"`
}

func (t *Tendrils) startHTTPServer() {
	if !t.EnableHTTPS {
		return
	}

	if err := ensureCert(); err != nil {
		log.Printf("[ERROR] failed to ensure certificate: %v", err)
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", t.handleAPIStatus)
	mux.HandleFunc("/api/config", t.handleAPIConfig)
	mux.Handle("/", http.FileServer(http.Dir("static")))

	log.Printf("[https] listening on :443")
	go func() {
		if err := http.ListenAndServeTLS(":443", certFile, keyFile, mux); err != nil {
			log.Printf("[ERROR] https server failed: %v", err)
		}
	}()
}

func ensureCert() error {
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			return nil
		}
	}

	log.Printf("[https] generating self-signed certificate")

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Tendrils"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	keyOut, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return err
	}

	return nil
}

func (t *Tendrils) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	status := t.GetStatus()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (t *Tendrils) handleAPIConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if t.config == nil {
		json.NewEncoder(w).Encode(&Config{})
		return
	}
	json.NewEncoder(w).Encode(t.config)
}

func (t *Tendrils) GetStatus() *StatusResponse {
	return &StatusResponse{
		Nodes:           t.getNodes(),
		Links:           t.getLinks(),
		MulticastGroups: t.getMulticastGroups(),
		ArtNetNodes:     t.getArtNetNodes(),
		DanteFlows:      t.getDanteFlows(),
	}
}

func (t *Tendrils) getNodes() []*Node {
	t.nodes.mu.RLock()
	defer t.nodes.mu.RUnlock()

	nodes := make([]*Node, 0, len(t.nodes.nodes))
	for _, node := range t.nodes.nodes {
		nodes = append(nodes, node)
	}
	sort.Slice(nodes, func(i, j int) bool {
		return sortorder.NaturalLess(nodes[i].DisplayName(), nodes[j].DisplayName())
	})

	return nodes
}

func (t *Tendrils) getLinks() []*Link {
	t.nodes.mu.RLock()
	defer t.nodes.mu.RUnlock()

	links := t.nodes.getDirectLinks()
	sort.Slice(links, func(i, j int) bool {
		if links[i].NodeA.DisplayName() != links[j].NodeA.DisplayName() {
			return sortorder.NaturalLess(links[i].NodeA.DisplayName(), links[j].NodeA.DisplayName())
		}
		if links[i].InterfaceA != links[j].InterfaceA {
			return sortorder.NaturalLess(links[i].InterfaceA, links[j].InterfaceA)
		}
		if links[i].NodeB.DisplayName() != links[j].NodeB.DisplayName() {
			return sortorder.NaturalLess(links[i].NodeB.DisplayName(), links[j].NodeB.DisplayName())
		}
		return sortorder.NaturalLess(links[i].InterfaceB, links[j].InterfaceB)
	})

	return links
}

func (t *Tendrils) getMulticastGroups() []*MulticastGroupMembers {
	t.nodes.mu.Lock()
	t.nodes.expireMulticastMemberships()
	t.nodes.mu.Unlock()

	t.nodes.mu.RLock()
	defer t.nodes.mu.RUnlock()

	groups := make([]*MulticastGroupMembers, 0, len(t.nodes.multicastGroups))
	for _, gm := range t.nodes.multicastGroups {
		groups = append(groups, gm)
	}
	sort.Slice(groups, func(i, j int) bool {
		return sortorder.NaturalLess(groups[i].Group.Name, groups[j].Group.Name)
	})

	return groups
}

func (t *Tendrils) getArtNetNodes() []*ArtNetNode {
	t.artnet.Expire()

	t.artnet.mu.RLock()
	defer t.artnet.mu.RUnlock()

	nodes := make([]*ArtNetNode, 0, len(t.artnet.nodes))
	for _, node := range t.artnet.nodes {
		nodes = append(nodes, node)
	}
	sort.Slice(nodes, func(i, j int) bool {
		return sortorder.NaturalLess(nodes[i].Node.DisplayName(), nodes[j].Node.DisplayName())
	})

	return nodes
}

func (t *Tendrils) getDanteFlows() []*DanteFlow {
	t.danteFlows.Expire()

	t.danteFlows.mu.RLock()
	defer t.danteFlows.mu.RUnlock()

	flows := make([]*DanteFlow, 0, len(t.danteFlows.flows))
	for _, flow := range t.danteFlows.flows {
		flows = append(flows, flow)
	}
	sort.Slice(flows, func(i, j int) bool {
		return sortorder.NaturalLess(flows[i].Source.DisplayName(), flows[j].Source.DisplayName())
	})

	return flows
}
