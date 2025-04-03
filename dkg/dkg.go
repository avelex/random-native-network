package dkg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"random-network-poc/rng"
	"sync"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/peer"
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
	rnd        *rng.Protocol

	board pedersen_dkg.Board

	Result *pedersen_dkg.Result

	mu          *sync.Mutex
	requests    map[string][][]byte
	requestWait map[string]chan struct{}
}

func NewNode(index uint32, privKey []byte, nonce []byte, board pedersen_dkg.Board, pub *pubsub.PubSub, peerId peer.ID) (*Node, error) {
	privateKey := Suite.Scalar().SetBytes(privKey)
	publicKey := Suite.Point().Mul(privateKey, nil)

	conf := pedersen_dkg.Config{
		Suite:     Suite,
		NewNodes:  Nodes,
		Threshold: Threshold,
		Longterm:  privateKey,
		Nonce:     nonce,
		Auth:      schnorr.NewScheme(Suite),
	}

	phaser := pedersen_dkg.NewTimePhaser(1 * time.Second)

	protocol, err := pedersen_dkg.NewProtocol(&conf, board, phaser, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create dkg protocol: %w", err)
	}

	n := &Node{
		index:       index,
		privateKey:  privateKey,
		publicKey:   publicKey,
		phaser:      phaser,
		board:       board,
		Protocol:    protocol,
		mu:          &sync.Mutex{},
		requests:    make(map[string][][]byte),
		requestWait: make(map[string]chan struct{}),
	}

	rnd, err := rng.NewProtocol(context.Background(), pub, peerId, n.SignVRF, n.HandleSignature)
	if err != nil {
		return nil, fmt.Errorf("failed to create rng protocol: %w", err)
	}

	n.rnd = rnd

	return n, nil
}

func (n *Node) StartDKG() {
	go n.phaser.Start()
}

func (n *Node) SignVRF(vrf rng.SignVRF) (rng.Signature, error) {
	if n.Result == nil {
		return rng.Signature{}, errors.New("DKG not completed")
	}

	data, err := hex.DecodeString(vrf.Data)
	if err != nil {
		return rng.Signature{}, fmt.Errorf("failed to decode data: %w", err)
	}

	sig, err := ThresholdBLS.Sign(n.Result.Key.PriShare(), data)
	if err != nil {
		return rng.Signature{}, fmt.Errorf("failed to sign data: %w", err)
	}

	return rng.Signature{
		RequestID: vrf.RequestID,
		Signature: hex.EncodeToString(sig),
	}, nil
}

func (n *Node) HandleSignature(signature rng.Signature) error {
	if n.Result == nil {
		return errors.New("DKG not completed")
	}

	sig, err := hex.DecodeString(signature.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	reqID := signature.RequestID

	n.mu.Lock()
	defer n.mu.Unlock()

	n.requests[reqID] = append(n.requests[reqID], sig)

	if len(n.requests[reqID]) >= Threshold {
		n.requestWait[reqID] <- struct{}{}
	}

	return nil
}

func (n *Node) WaitRNGRound(requestID string) <-chan struct{} {
	return n.requestWait[requestID]
}

func (n *Node) StartRandomNumberGeneration(requestID string, data []byte) error {
	if err := n.rnd.Start(requestID, data); err != nil {
		return fmt.Errorf("failed to start rng protocol: %w", err)
	}

	n.requestWait[requestID] = make(chan struct{}, 1)

	sig, err := n.Sign(data)
	if err != nil {
		return fmt.Errorf("failed to sign data: %w", err)
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	n.requests[requestID] = append(n.requests[requestID], sig)

	if len(n.requests[requestID]) >= Threshold {
		n.requestWait[requestID] <- struct{}{}
	}

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
