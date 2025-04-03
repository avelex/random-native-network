package p2p

import (
	"context"
	"log"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

const DiscoveryServiceTag = "random-network-mdns"

// discoveryNotifee gets notified when we find a new peer via mDNS discovery
type discoveryNotifee struct {
	h host.Host
}

func (d *discoveryNotifee) HandlePeerFound(info peer.AddrInfo) {
	log.Printf("Discovered new peer %s\n", info.ID)
	err := d.h.Connect(context.Background(), info)
	if err != nil {
		log.Printf("Error connecting to peer %s: %s\n", info.ID, err)
	}
}
