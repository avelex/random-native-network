package rng

import "github.com/libp2p/go-libp2p/core/peer"

type SignVRF struct {
	RequestID string
	Sender    peer.ID
	Data      string
}

type Signature struct {
	RequestID string
	Signature string
}
