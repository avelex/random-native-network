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
	"time"

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
	phaser     *pedersen_dkg.TimePhaser
	Protocol   *pedersen_dkg.Protocol

	board *HttpBoard

	Result *pedersen_dkg.Result

	requests map[string][][]byte
}

func NewNode(index uint32, privKey []byte, nonce []byte, board *HttpBoard) (*Node, error) {
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

	phaser := pedersen_dkg.NewTimePhaser(1 * time.Second)

	protocol, err := pedersen_dkg.NewProtocol(&conf, board, phaser, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create dkg protocol: %w", err)
	}

	return &Node{
		index:      index,
		privateKey: privateKey,
		publicKey:  publicKey,
		phaser:     phaser,
		board:      board,
		Protocol:   protocol,
		requests:   make(map[string][][]byte),
	}, nil
}

func (n *Node) StartDKG() {
	go n.phaser.Start()
}

// ProcessDealBundle processes a received deal bundle and returns a response bundle
func (n *Node) SaveDeal(dealBundle *pedersen_dkg.DealBundle) {
	n.board.ReceiveDealBundle(*dealBundle)
}

// ProcessResponseBundle processes a received response bundle
func (n *Node) SaveResponseBundle(responseBundle *pedersen_dkg.ResponseBundle) {
	// Send response bundle to the specified peer
	if responseBundle != nil {
		n.board.ReceiveResponseBundle(*responseBundle)
	} else {
		n.board.ReceiveResponseBundle(pedersen_dkg.ResponseBundle{})
	}
}

func (n *Node) SaveJustificationBundle(justificationBundle *pedersen_dkg.JustificationBundle) {
	// Send response bundle to the specified peer
	n.board.ReceiveJustificationBundle(*justificationBundle)
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

// HexToBytes converts a hex string to bytes
func HexToBytes(hexStr string) ([]byte, error) {
	return hex.DecodeString(hexStr)
}
