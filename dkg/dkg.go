package dkg

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"

	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing/bn256"
	"go.dedis.ch/kyber/v4/share"
	pedersen_dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	"go.dedis.ch/kyber/v4/sign/bls"
	"go.dedis.ch/kyber/v4/sign/schnorr"
	"go.dedis.ch/kyber/v4/sign/tbls"
)

var (
	Suite        = bn256.NewSuiteG2()
	SigSuite     = bn256.NewSuiteG1()
	ThresholdBLS = tbls.NewThresholdSchemeOnG1(SigSuite)
)

type Node struct {
	index      uint32
	privateKey kyber.Scalar
	publicKey  kyber.Point
	*pedersen_dkg.DistKeyGenerator

	deals           []*pedersen_dkg.DealBundle
	responseBundles []*pedersen_dkg.ResponseBundle

	Result *pedersen_dkg.Result

	requests map[string][][]byte
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
		requests:         make(map[string][][]byte),
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

func (n *Node) SendAndCollectVrfSignatures(requestID string, peerURLs []string, data []byte) error {
	for _, peerURL := range peerURLs {
		// Skip sending to self (we'll handle our own response separately)
		if strings.Contains(peerURL, fmt.Sprintf(":800%d", n.index)) {
			continue
		}

		signature, err := n.sendSignVrfRequest(peerURL, data)
		if err != nil {
			log.Printf("Failed to send sign VRF request to %s: %v\n", peerURL, err)
			// Continue with other peers even if one fails
			continue
		}

		log.Printf("Received signature from %s: %v\n", peerURL, hex.EncodeToString(signature))

		n.requests[requestID] = append(n.requests[requestID], signature)
	}

	sig, err := n.Sign(data)
	if err != nil {
		return fmt.Errorf("failed to sign data: %w", err)
	}

	n.requests[requestID] = append(n.requests[requestID], sig)

	return nil
}

func (n *Node) RecoverBLSSignature(requestID string, data []byte) ([]byte, error) {
	sigShares := n.requests[requestID]
	if len(sigShares) == 0 {
		return nil, errors.New("no signature shares")
	}

	poly := share.NewPubPoly(Suite, Suite.Point().Base(), n.Result.Key.Commits)

	sig, err := ThresholdBLS.Recover(poly, data, sigShares, Threshold, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to recover signature: %w", err)
	}

	return sig, nil
}

func (n *Node) VerifyBLSSignature(data []byte, signature []byte) error {
	poly := share.NewPubPoly(Suite, Suite.Point().Base(), n.Result.Key.Commits)

	blsSchema := bls.NewSchemeOnG1(SigSuite)

	return blsSchema.Verify(poly.Commit(), data, signature)
}

func (n *Node) GenerateRandomNumber(tblsSig []byte) *big.Int {
	hash := sha256.Sum256(tblsSig)
	return big.NewInt(0).SetBytes(hash[:])
}

func (n *Node) sendSignVrfRequest(peerURL string, data []byte) ([]byte, error) {
	url := peerURL + "/sign_vrf"

	// Convert sign VRF request to JSON
	requestBytes, err := json.Marshal(map[string]string{
		"data": hex.EncodeToString(data),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to encode sign VRF request: %w", err)
	}

	buf := bytes.NewBuffer(requestBytes)

	resp, err := http.Post(url, "application/json", buf)
	if err != nil {
		return nil, fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		buf.Reset()
		if _, err := io.Copy(buf, resp.Body); err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}
		return nil, fmt.Errorf("received non-OK response: %s | %d", buf.String(), resp.StatusCode)
	}

	// Parse response
	var response map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	signature, ok := response["signature"]
	if !ok {
		return nil, errors.New("missing signature in response")
	}

	return hex.DecodeString(signature)
}

func (n *Node) Sign(data []byte) ([]byte, error) {
	if n.Result == nil {
		return nil, errors.New("DKG not completed")
	}
	return ThresholdBLS.Sign(n.Result.Key.PriShare(), data)
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
