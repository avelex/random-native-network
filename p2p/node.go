package p2p

import (
	"context"
	"fmt"

	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
)

type NodeP2P struct {
	Host    host.Host
	service mdns.Service
	ps      *pubsub.PubSub
}

func NewNode(ctx context.Context) (*NodeP2P, error) {
	h, err := libp2p.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create host: %w", err)
	}

	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		return nil, fmt.Errorf("failed to create pubsub: %w", err)
	}

	return &NodeP2P{
		Host:    h,
		service: mdns.NewMdnsService(h, DiscoveryServiceTag, &discoveryNotifee{h: h}),
		ps:      ps,
	}, nil
}

func (n *NodeP2P) DiscoverPeers(ctx context.Context) error {
	return n.service.Start()
}

func (n *NodeP2P) PubSub() *pubsub.PubSub {
	return n.ps
}

func (n *NodeP2P) ID() peer.ID {
	return n.Host.ID()
}
