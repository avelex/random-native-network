package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

var knownPeersMap = map[int]string{
	0: "http://localhost:8000",
	1: "http://localhost:8001",
	2: "http://localhost:8002",
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

	board := dkg.NewHttpBoard(uint32(*index), http.DefaultClient, knownPeersMap)

	// Create DKG node
	node, err := dkg.NewNode(uint32(*index), privKeyBytes, nonceBytes, board)
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

	log.Println("Starting DKG protocol")
	node.StartDKG()

	log.Println("Waiting for DKG to finish")
	result := <-node.Protocol.WaitEnd()

	if result.Error != nil {
		log.Fatalf("DKG failed: %v", result.Error)
	}

	node.Result = result.Result

	pubBytes, err := node.Result.Key.Public().MarshalBinary()
	if err != nil {
		log.Fatalf("Failed to marshal public point: %v", err)
	}

	log.Printf("Public: %v\n", hex.EncodeToString(pubBytes))

	if *index == 0 {
		time.Sleep(2 * time.Second)

		prevBlockHash := "0x0000000000000000000000000000000000000000000000000000000000000000"
		nextBlockNumber := "1"
		seed := pedersen_dkg.GetNonce()
		data := append([]byte(prevBlockHash), []byte(nextBlockNumber)...)
		data = append(data, seed...)

		hash := sha256.Sum256(data)
		requestID := hex.EncodeToString(hash[:])

		log.Println("Initiating VRF generation")

		if err := node.SendAndCollectVrfSignatures(requestID, knownPeers, hash[:]); err != nil {
			log.Fatalf("Failed to send and collect VRF signatures: %v", err)
		}

		sig, err := node.RecoverBLSSignature(requestID, hash[:])
		if err != nil {
			log.Fatalf("Failed to recover signature: %v", err)
		}

		log.Printf("Threshold BLS signature: %v\n", hex.EncodeToString(sig))

		if err := node.VerifyBLSSignature(hash[:], sig); err != nil {
			log.Fatalf("Failed to verify signature: %v", err)
		}

		log.Println("Signature is valid!")

		randomNumber := node.GenerateRandomNumber(sig)
		log.Printf("Random number: %v\n", randomNumber)
	}

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
	s.router.HandleFunc("/justifications", s.handleJustifications)
	s.router.HandleFunc("/sign_vrf", s.handleSignVrf)

	return s
}

// handleHealth handles the health check endpoint
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK")
}

func (s *Server) handleSignVrf(w http.ResponseWriter, r *http.Request) {
	type SignVrfRequest struct {
		Data string `json:"data"`
	}

	var req SignVrfRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode request body: %v", err), http.StatusBadRequest)
		return
	}

	data, err := hex.DecodeString(req.Data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode data: %v", err), http.StatusBadRequest)
		return
	}

	// Sign the data
	signature, err := s.node.Sign(data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to sign data: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"signature": hex.EncodeToString(signature),
	})
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
	s.node.SaveDeal(dealBundle)

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
	s.node.SaveResponseBundle(bundle)

	// Return success
	w.WriteHeader(http.StatusOK)
}

// handleJustifications processes incoming justification bundles
func (s *Server) handleJustifications(w http.ResponseWriter, r *http.Request) {
	defer func() {
		log.Println("Handle justification bundle completed")
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

	// Decode the justification bundle from the request
	justificationBundle, err := dkg.JustificationBundleFromJSON(body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode justification bundle: %v", err), http.StatusBadRequest)
		return
	}

	// Process the justification bundle
	s.node.SaveJustificationBundle(justificationBundle)

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
