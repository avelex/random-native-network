package dkg

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/peer"
	pedersen_dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
)

const (
	Topic = "dkg"
)

var _ pedersen_dkg.Board = (*BoardP2P)(nil)

type BoardP2P struct {
	self peer.ID

	ctx    context.Context
	pubsub *pubsub.PubSub
	topic  *pubsub.Topic
	sub    *pubsub.Subscription

	deals chan pedersen_dkg.DealBundle
	resps chan pedersen_dkg.ResponseBundle
	justs chan pedersen_dkg.JustificationBundle
}

func NewBoardP2P(ctx context.Context, ps *pubsub.PubSub, self peer.ID) (*BoardP2P, error) {
	topic, err := ps.Join(Topic)
	if err != nil {
		return nil, fmt.Errorf("failed to join topic %s: %w", Topic, err)
	}

	sub, err := topic.Subscribe()
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to topic %s: %w", Topic, err)
	}

	b := &BoardP2P{
		self:   self,
		ctx:    ctx,
		pubsub: ps,
		topic:  topic,
		sub:    sub,
		deals:  make(chan pedersen_dkg.DealBundle, 3),
		resps:  make(chan pedersen_dkg.ResponseBundle, 3),
		justs:  make(chan pedersen_dkg.JustificationBundle, 3),
	}

	go b.readLoop()

	return b, nil
}

func (b *BoardP2P) PushDeals(bundle *pedersen_dkg.DealBundle) {
	msg, err := NewDealBundleMessage(bundle)
	if err != nil {
		log.Printf("Error marshalling deal bundle: %s\n", err)
		return
	}

	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("Error marshalling message: %s\n", err)
		return
	}

	if err := b.topic.Publish(b.ctx, data); err != nil {
		log.Printf("Error publishing deal bundle: %s\n", err)
	}

	b.deals <- *bundle
}

func (b *BoardP2P) IncomingDeal() <-chan pedersen_dkg.DealBundle {
	return b.deals
}

func (b *BoardP2P) PushResponses(bundle *pedersen_dkg.ResponseBundle) {
	msg, err := NewResponseBundleMessage(bundle)
	if err != nil {
		log.Printf("Error marshalling response bundle: %s\n", err)
		return
	}

	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("Error marshalling message: %s\n", err)
		return
	}

	if err := b.topic.Publish(b.ctx, data); err != nil {
		log.Printf("Error publishing response bundle: %s\n", err)
	}

	b.resps <- *bundle
}

func (b *BoardP2P) IncomingResponse() <-chan pedersen_dkg.ResponseBundle {
	return b.resps
}

func (b *BoardP2P) PushJustifications(bundle *pedersen_dkg.JustificationBundle) {
	msg, err := NewJustificationBundleMessage(bundle)
	if err != nil {
		log.Printf("Error marshalling justification bundle: %s\n", err)
		return
	}

	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("Error marshalling message: %s\n", err)
		return
	}

	if err := b.topic.Publish(b.ctx, data); err != nil {
		log.Printf("Error publishing justification bundle: %s\n", err)
	}

	b.justs <- *bundle
}

func (b *BoardP2P) IncomingJustification() <-chan pedersen_dkg.JustificationBundle {
	return b.justs
}

func (b *BoardP2P) readLoop() {
	for {
		msg, err := b.sub.Next(b.ctx)
		if err != nil {
			log.Printf("Error reading message: %s\n", err)
			return
		}

		// only forward messages delivered by others
		if msg.ReceivedFrom == b.self {
			continue
		}

		m := new(Message)

		if err = json.Unmarshal(msg.Data, m); err != nil {
			log.Printf("Error unmarshalling message: %s\n", err)
			continue
		}

		switch m.Type {
		case MessageDealBundle:
			bundle, err := DealBundleFromJSON(m.Data)
			if err != nil {
				log.Printf("Error unmarshalling deal bundle: %s\n", err)
				continue
			}

			b.deals <- *bundle
		case MessageResponseBundle:
			bundle, err := ResponseBundleFromJSON(m.Data)
			if err != nil {
				log.Printf("Error unmarshalling response bundle: %s\n", err)
				continue
			}

			b.resps <- *bundle
		case MessageJustificationBundle:
			bundle, err := JustificationBundleFromJSON(m.Data)
			if err != nil {
				log.Printf("Error unmarshalling justification bundle: %s\n", err)
				continue
			}

			b.justs <- *bundle
		default:
			log.Printf("Unknown message type: %d\n", m.Type)
		}
	}
}
