package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"log"
	"time"

	"random-network-poc/dkg"
	"random-network-poc/p2p"

	pedersen_dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
)

var (
	index = flag.Uint("index", 0, "Node index")
	pk    = flag.String("pk", "", "Private key in hex format")
	nonce = flag.String("nonce", "", "Nonce in hex format")
)

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

	p2pNode, err := p2p.NewNode(context.Background())
	if err != nil {
		log.Fatalf("Failed to create P2P node: %v", err)
	}

	log.Println("Node ID:", p2pNode.ID())

	log.Println("Discovering peers...")
	if err := p2pNode.DiscoverPeers(context.Background()); err != nil {
		log.Fatalf("Failed to discover peers: %v", err)
	}

	board, err := dkg.NewBoardP2P(context.Background(), p2pNode.PubSub(), p2pNode.ID())
	if err != nil {
		log.Fatalf("Failed to create board: %v", err)
	}

	// Create DKG node
	node, err := dkg.NewNode(uint32(*index), privKeyBytes, nonceBytes, board, p2pNode.PubSub(), p2pNode.ID())
	if err != nil {
		log.Fatalf("Failed to create DKG node: %v", err)
	}

	for len(p2pNode.PubSub().ListPeers(dkg.Topic)) != 2 {
	}

	log.Println("All peers discovered!")

	time.Sleep(1 * time.Second)

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

		if err := node.StartRandomNumberGeneration(requestID, hash[:]); err != nil {
			log.Fatalf("Failed to start random number generation: %v", err)
		}

		<-node.WaitRNGRound(requestID)

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
