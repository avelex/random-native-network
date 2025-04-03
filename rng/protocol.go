package rng

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	SignVrfInput  = "sign_vrf_input"
	SignVrfOutput = "sign_vrf_output"
)

type HandleSignVRF func(SignVRF) (Signature, error)
type HandleSignature func(Signature) error

type Protocol struct {
	self peer.ID
	ctx  context.Context
	ps   *pubsub.PubSub

	input  *pubsub.Topic
	output *pubsub.Topic

	subIn  *pubsub.Subscription
	subOut *pubsub.Subscription

	handleSignVRF   HandleSignVRF
	handleSignature HandleSignature
}

func NewProtocol(ctx context.Context, ps *pubsub.PubSub, self peer.ID, handleSignVRF HandleSignVRF, handleSignature HandleSignature) (*Protocol, error) {
	input, err := ps.Join(SignVrfInput)
	if err != nil {
		return nil, fmt.Errorf("failed to join topic %s: %w", SignVrfInput, err)
	}

	output, err := ps.Join(SignVrfOutput)
	if err != nil {
		return nil, fmt.Errorf("failed to join topic %s: %w", SignVrfOutput, err)
	}

	subIn, err := input.Subscribe()
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to topic %s: %w", SignVrfInput, err)
	}

	subOut, err := output.Subscribe()
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to topic %s: %w", SignVrfOutput, err)
	}

	p := &Protocol{
		ctx:             ctx,
		ps:              ps,
		self:            self,
		input:           input,
		output:          output,
		subIn:           subIn,
		subOut:          subOut,
		handleSignVRF:   handleSignVRF,
		handleSignature: handleSignature,
	}

	go p.readSubIn()
	go p.readSubOut()

	return p, nil
}

func (p *Protocol) Start(requestID string, data []byte) error {
	signVRF := SignVRF{
		RequestID: requestID,
		Sender:    p.self,
		Data:      hex.EncodeToString(data),
	}

	data, err := json.Marshal(signVRF)
	if err != nil {
		return fmt.Errorf("failed to marshal signVRF: %w", err)
	}

	if err := p.input.Publish(p.ctx, data); err != nil {
		return fmt.Errorf("failed to publish signVRF: %w", err)
	}

	return nil
}

func (p *Protocol) readSubIn() {
	for {
		msg, err := p.subIn.Next(p.ctx)
		if err != nil {
			log.Printf("Error reading message: %s\n", err)
			return
		}

		if msg.ReceivedFrom == p.self {
			continue
		}

		var signVRF SignVRF

		if err := json.Unmarshal(msg.Data, &signVRF); err != nil {
			log.Printf("Error unmarshalling message: %s\n", err)
			continue
		}

		signature, err := p.handleSignVRF(signVRF)
		if err != nil {
			log.Printf("Error handling signVRF: %s\n", err)
			continue
		}

		send, err := json.Marshal(&signature)
		if err != nil {
			log.Printf("Error marshalling signature: %s\n", err)
			continue
		}

		if err := p.output.Publish(p.ctx, send); err != nil {
			log.Printf("Error publishing message: %s\n", err)
			continue
		}
	}
}

func (p *Protocol) readSubOut() {
	for {
		msg, err := p.subOut.Next(p.ctx)
		if err != nil {
			log.Printf("Error reading message: %s\n", err)
			return
		}

		if msg.ReceivedFrom == p.self {
			continue
		}

		var signature Signature

		if err := json.Unmarshal(msg.Data, &signature); err != nil {
			log.Printf("Error unmarshalling message: %s\n", err)
			continue
		}

		if err := p.handleSignature(signature); err != nil {
			log.Printf("Error handling signature: %s\n", err)
			continue
		}
	}
}
