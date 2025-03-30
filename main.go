package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"random-network-poc/dkg"

	pedersen_dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
)

var (
	index    = flag.Uint("index", 0, "Node index")
	pk       = flag.String("pk", "", "Private key in hex format")
	nonce    = flag.String("nonce", "", "Nonce in hex format")
	httpPort = flag.Uint("http_port", 8000, "HTTP server port")
)

// Known peer addresses
var knownPeers = []string{
	"http://localhost:8000",
	"http://localhost:8001",
	"http://localhost:8002",
}

func main() {
	flag.Parse()

	if *pk == "" {
		log.Fatal("Private key is required")
	}

	// Convert hex private key to bytes
	privKeyBytes, err := dkg.HexToBytes(*pk)
	if err != nil {
		log.Fatalf("Failed to decode private key: %v", err)
	}

	// Convert hex nonce to bytes
	nonceBytes, err := dkg.HexToBytes(*nonce)
	if err != nil {
		log.Fatalf("Failed to decode nonce: %v", err)
	}

	// Create DKG node
	node, err := dkg.NewNode(uint32(*index), privKeyBytes, nonceBytes)
	if err != nil {
		log.Fatalf("Failed to create DKG node: %v", err)
	}

	// Create HTTP server
	server := NewServer(node)

	// Start server in a goroutine
	go func() {
		addr := fmt.Sprintf(":%d", *httpPort)
		log.Printf("Starting HTTP server on %s", addr)
		if err := http.ListenAndServe(addr, server.router); err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Wait for all peers to be healthy
	log.Println("Waiting for all peers to be healthy...")
	if err := waitForPeers(); err != nil {
		log.Fatalf("Failed waiting for peers: %v", err)
	}
	log.Println("All peers are healthy!")

	if err := node.GenerateDeals(); err != nil {
		log.Fatalf("Failed to generate deals: %v", err)
	}

	time.Sleep(5 * time.Second)

	log.Println("Deals generated!")

	if err := node.SendDeals(knownPeers); err != nil {
		log.Fatalf("Failed to send deals: %v", err)
	}

	log.Println("Deals sent!")

	log.Println("Waiting for others deals for processing...")
	time.Sleep(10 * time.Second)

	if err := node.ProcessSavedDeals(); err != nil {
		log.Fatalf("Failed to process saved deals: %v", err)
	}

	log.Println("Deals processed!")

	if err := node.SendResponse(knownPeers); err != nil {
		log.Fatalf("Failed to send response: %v", err)
	}

	log.Println("Response sent!")

	log.Println("Waiting for others responses for processing...")
	time.Sleep(10 * time.Second)

	if err := node.ProcessResponseBundles(); err != nil {
		log.Fatalf("Failed to process saved responses: %v", err)
	}

	log.Println("Responses processed!")

	pubBytes, err := node.Result.Key.Public().MarshalBinary()
	if err != nil {
		log.Fatalf("Failed to marshal public point: %v", err)
	}

	fmt.Printf("Public: %v\n", hex.EncodeToString(pubBytes))

	// Keep the program running
	select {}
}

// Server represents the HTTP server with DKG node
type Server struct {
	node   *dkg.Node
	router *http.ServeMux
	peers  []string
}

// NewServer creates a new HTTP server with the given DKG node
func NewServer(node *dkg.Node) *Server {
	// Create peer URLs without the /health suffix
	peers := make([]string, 0, len(knownPeers))
	for _, peerURL := range knownPeers {
		// Remove the /health suffix
		peer := strings.TrimSuffix(peerURL, "/health")
		peers = append(peers, peer)
	}
	s := &Server{
		node:   node,
		router: http.NewServeMux(),
		peers:  peers,
	}

	// Register handlers
	s.router.HandleFunc("/health", s.handleHealth)
	s.router.HandleFunc("/deals", s.handleDeals)
	s.router.HandleFunc("/responses", s.handleResponses)

	return s
}

// handleHealth handles the health check endpoint
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK")
}

// handleDeals processes incoming deal bundles and returns response bundles
func (s *Server) handleDeals(w http.ResponseWriter, r *http.Request) {
	defer func() {
		log.Println("Handle deal bundle completed")
	}()

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read request body: %v", err), http.StatusBadRequest)
		return
	}

	// Decode the deal bundle from the request
	dealBundle, err := dkg.DealBundleFromJSON(body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode deal bundle: %v", err), http.StatusBadRequest)
		return
	}

	// Process the deal bundle
	err = s.node.SaveDeal(dealBundle)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to process deal bundle: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleResponses processes incoming response bundles
func (s *Server) handleResponses(w http.ResponseWriter, r *http.Request) {
	defer func() {
		log.Println("Handle response bundle completed")
	}()

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read request body: %v", err), http.StatusBadRequest)
		return
	}

	var bundle *pedersen_dkg.ResponseBundle

	// Decode the response bundle from the request
	if responseBundle, err := dkg.ResponseBundleFromJSON(body); err == nil && len(responseBundle.Signature) > 0 {
		bundle = responseBundle
	}

	// Process the response bundle
	if err := s.node.SaveResponseBundle(bundle); err != nil {
		http.Error(w, fmt.Sprintf("Failed to process response bundle: %v", err), http.StatusInternalServerError)
		return
	}

	// Return success
	w.WriteHeader(http.StatusOK)
}

// waitForPeers waits for all known peers to be healthy
func waitForPeers() error {
	// Determine current node's URL to avoid self-check
	currentNodeURL := fmt.Sprintf("http://localhost:%d/health", *httpPort)
	client := &http.Client{
		Timeout: 1 * time.Second,
	}

	maxRetries := 30
	retryInterval := 1 * time.Second

	for retry := 0; retry < maxRetries; retry++ {
		allHealthy := true

		for _, peerURL := range knownPeers {
			peerURL = peerURL + "/health"
			// Skip health check for self
			if peerURL == currentNodeURL {
				continue
			}
			resp, err := client.Get(peerURL)
			if err != nil || resp.StatusCode != http.StatusOK {
				allHealthy = false
				log.Printf("Peer %s is not healthy yet", peerURL)
				break
			}

			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
		}

		if allHealthy {
			return nil
		}

		log.Printf("Not all peers are healthy yet, retrying in %v...", retryInterval)
		time.Sleep(retryInterval)
	}

	return fmt.Errorf("timed out waiting for peers to be healthy")
}
