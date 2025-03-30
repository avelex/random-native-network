package dkg

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing/bn256"
	pedersen_dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	"go.dedis.ch/kyber/v4/sign/schnorr"
)

var Suite = bn256.NewSuiteG2()
var SigSuite = bn256.NewSuiteG1()

type Node struct {
	index      uint32
	privateKey kyber.Scalar
	publicKey  kyber.Point
	*pedersen_dkg.DistKeyGenerator

	deals           []*pedersen_dkg.DealBundle
	responseBundles []*pedersen_dkg.ResponseBundle

	Result *pedersen_dkg.Result
}

func NewNode(index uint32, privKey []byte, nonce []byte) (*Node, error) {
	privateKey := Suite.Scalar().SetBytes(privKey)
	publicKey := Suite.Point().Mul(privateKey, nil)

	conf := pedersen_dkg.Config{
		Suite:     Suite,
		NewNodes:  Nodes,
		Threshold: Threshold,
		Longterm:  privateKey,
		Nonce:     nonce,
		Auth:      schnorr.NewScheme(Suite),
		Log:       &Logger{},
	}

	gen, err := pedersen_dkg.NewDistKeyHandler(&conf)
	if err != nil {
		return nil, fmt.Errorf("failed to create dkg handler: %w", err)
	}

	return &Node{
		index:            index,
		privateKey:       privateKey,
		publicKey:        publicKey,
		DistKeyGenerator: gen,
	}, nil
}

func (n *Node) GenerateDeals() error {
	dealBundle, err := n.Deals()
	if err != nil {
		return fmt.Errorf("failed to generate deals: %w", err)
	}

	n.deals = append(n.deals, dealBundle)

	return nil
}

func (n *Node) SendDeals(peerURLs []string) error {
	for _, peerURL := range peerURLs {
		// Skip sending to self (we'll handle our own deal separately)
		if strings.Contains(peerURL, fmt.Sprintf(":800%d", n.index)) {
			continue
		}

		if err := n.sendDealBundle(peerURL, n.deals[0]); err != nil {
			fmt.Printf("Failed to send deal to %s: %v\n", peerURL, err)
			// Continue with other peers even if one fails
			continue
		}
	}

	return nil
}

// ProcessDealBundle processes a received deal bundle and returns a response bundle
func (n *Node) SaveDeal(dealBundle *pedersen_dkg.DealBundle) error {
	n.deals = append(n.deals, dealBundle)
	return nil
}

func (n *Node) ProcessSavedDeals() error {
	responseBundle, err := n.ProcessDeals(n.deals)
	if err != nil {
		return fmt.Errorf("failed to process deals: %w", err)
	}

	if responseBundle != nil {
		n.responseBundles = append(n.responseBundles, responseBundle)
	}

	return nil
}

func (n *Node) SendResponse(peerURLs []string) error {
	for _, peerURL := range peerURLs {
		// Skip sending to self (we'll handle our own response separately)
		if strings.Contains(peerURL, fmt.Sprintf(":800%d", n.index)) {
			continue
		}

		if err := n.sendResponseBundle(peerURL); err != nil {
			fmt.Printf("Failed to send response to %s: %v\n", peerURL, err)
			// Continue with other peers even if one fails
			continue
		}
	}

	return nil
}

// ProcessResponseBundle processes a received response bundle
func (n *Node) SaveResponseBundle(responseBundle *pedersen_dkg.ResponseBundle) error {
	if responseBundle != nil {
		n.responseBundles = append(n.responseBundles, responseBundle)
		fmt.Printf("Save Response: %v\n", responseBundle)
	}

	return nil
}

func (n *Node) ProcessResponseBundles() error {
	result, justificationBundle, err := n.ProcessResponses(n.responseBundles)
	if err != nil {
		return fmt.Errorf("failed to process responses: %w", err)
	}

	// If we got a result, store it
	if result != nil {
		n.Result = result
		fmt.Printf("DKG completed successfully for node %d\n", n.index)
	}

	// If we need to send justifications, we would handle that here
	if justificationBundle != nil {
		// In a complete implementation, we would send the justification bundle to peers
		fmt.Printf("Justification bundle generated for node %d\n", n.index)
	}

	return nil
}

func (n *Node) sendResponseBundle(peerURL string) error {
	url := peerURL + "/responses"

	bundle := &pedersen_dkg.ResponseBundle{
		ShareIndex: n.index,
	}

	if len(n.responseBundles) > 0 {
		bundle = n.responseBundles[0]
	}

	// Convert response bundle to JSON
	responseBytes, err := ResponseBundleToJSON(bundle)
	if err != nil {
		return fmt.Errorf("failed to encode response bundle: %w", err)
	}

	buf := bytes.NewBuffer(responseBytes)

	resp, err := http.Post(url, "application/json", buf)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		buf.Reset()
		if _, err := io.Copy(buf, resp.Body); err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}

		return fmt.Errorf("received non-OK response: %s | %d", buf.String(), resp.StatusCode)
	}

	return nil
}

// sendDealBundle sends a deal bundle to a peer via HTTP and returns the response bundle
func (n *Node) sendDealBundle(peerURL string, dealBundle *pedersen_dkg.DealBundle) error {
	url := peerURL + "/deals"

	// Convert deal bundle to JSON
	dealBytes, err := DealBundleToJSON(dealBundle)
	if err != nil {
		return fmt.Errorf("failed to encode deal bundle: %w", err)
	}

	buf := bytes.NewBuffer(dealBytes)

	resp, err := http.Post(url, "application/json", buf)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		buf.Reset()
		if _, err := io.Copy(buf, resp.Body); err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}
		return fmt.Errorf("received non-OK response: %s | %d", buf.String(), resp.StatusCode)
	}

	return nil
}

// HexToBytes converts a hex string to bytes
func HexToBytes(hexStr string) ([]byte, error) {
	return hex.DecodeString(hexStr)
}
