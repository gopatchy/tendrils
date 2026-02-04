package tendrils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
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
	Config         *Config                 `json:"config"`
	Nodes          []*Node                 `json:"nodes"`
	Links          []*Link                 `json:"links"`
	Errors         []*Error                `json:"errors,omitempty"`
	BroadcastStats *BroadcastStatsResponse `json:"broadcast_stats,omitempty"`
}


func noCacheHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		h.ServeHTTP(w, r)
	})
}

func (t *Tendrils) startHTTPServer() {
	if err := ensureCert(); err != nil {
		log.Printf("[ERROR] failed to ensure certificate: %v", err)
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/tendrils/api/status", t.handleAPIStatus)
	mux.HandleFunc("/tendrils/api/errors/clear", t.handleClearError)
	mux.HandleFunc("/tendrils/api/nodes/remove", t.handleRemoveNode)
	mux.Handle("/tendrils/mcp/", t.newMCPServer())
	mux.Handle("/", noCacheHandler(http.FileServer(http.Dir("static"))))

	log.Printf("[https] listening on :443")
	go func() {
		if err := http.ListenAndServeTLS(":443", certFile, keyFile, mux); err != nil {
			log.Printf("[ERROR] https server failed: %v", err)
		}
	}()

	log.Printf("[http] listening on :80")
	go func() {
		if err := http.ListenAndServe(":80", mux); err != nil {
			log.Printf("[ERROR] http server failed: %v", err)
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
	if r.Header.Get("Accept") == "text/event-stream" {
		t.handleAPIStatusStream(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	data, err := t.GetStatusJSON()
	if err != nil {
		log.Printf("[ERROR] failed to encode status: %v", err)
		return
	}
	w.Write(data)
}

func (t *Tendrils) GetStatusJSON() ([]byte, error) {
	t.nodes.mu.Lock()
	t.nodes.expireMulticastMemberships()
	t.nodes.expireArtNet()
	t.nodes.expireSACN()
	t.nodes.expireDante()
	t.nodes.mu.Unlock()

	t.nodes.mu.RLock()
	defer t.nodes.mu.RUnlock()

	var broadcastStats *BroadcastStatsResponse
	if t.broadcast != nil {
		stats := t.broadcast.GetStats()
		broadcastStats = &stats
	}
	config := t.config
	if config == nil {
		config = &Config{}
	}
	return json.Marshal(&StatusResponse{
		Config:         config,
		Nodes:          t.getNodesLocked(),
		Links:          t.getLinksLocked(),
		Errors:         t.errors.GetErrors(),
		BroadcastStats: broadcastStats,
	})
}

func (t *Tendrils) handleClearError(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.URL.Query().Get("all") == "true" {
		t.errors.ClearAllErrors()
	} else if id := r.URL.Query().Get("id"); id != "" {
		t.errors.ClearError(id)
	} else {
		http.Error(w, "missing id or all parameter", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (t *Tendrils) handleRemoveNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "missing id parameter", http.StatusBadRequest)
		return
	}

	if err := t.nodes.RemoveNodeByID(id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("removed node %s", id)
	t.NotifyUpdate()
	w.WriteHeader(http.StatusOK)
}

func (t *Tendrils) handleAPIStatusStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	subID, updateCh := t.subscribeSSE()
	defer t.unsubscribeSSE(subID)

	sendStatus := func() error {
		data, err := t.GetStatusJSON()
		if err != nil {
			log.Printf("[ERROR] failed to marshal status: %v", err)
			return err
		}
		_, err = fmt.Fprintf(w, "event: status\ndata: %s\n\n", data)
		if err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}

	if err := sendStatus(); err != nil {
		return
	}

	heartbeat := time.NewTicker(3 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-updateCh:
			if err := sendStatus(); err != nil {
				return
			}
		case <-heartbeat.C:
			_, err := fmt.Fprintf(w, ": heartbeat\n\n")
			if err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (t *Tendrils) getNodesLocked() []*Node {
	nodes := make([]*Node, 0, len(t.nodes.nodes))
	for _, node := range t.nodes.nodes {
		nodes = append(nodes, node)
	}

	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].DisplayName() != nodes[j].DisplayName() {
			return sortorder.NaturalLess(nodes[i].DisplayName(), nodes[j].DisplayName())
		}
		if nodes[i].FirstIP() != nodes[j].FirstIP() {
			return sortorder.NaturalLess(nodes[i].FirstIP(), nodes[j].FirstIP())
		}
		return sortorder.NaturalLess(nodes[i].FirstMAC(), nodes[j].FirstMAC())
	})

	return nodes
}


func (t *Tendrils) getLinksLocked() []*Link {
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
