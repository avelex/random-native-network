package dkg

import (
	"bytes"
	"io"
	"log"
	"net/http"

	pedersen_dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
)

var _ pedersen_dkg.Board = (*HttpBoard)(nil)

type HttpBoard struct {
	index  uint32
	client *http.Client
	peers  map[int]string

	deals chan pedersen_dkg.DealBundle
	resps chan pedersen_dkg.ResponseBundle
	justs chan pedersen_dkg.JustificationBundle
}

func NewHttpBoard(index uint32, client *http.Client, peers map[int]string) *HttpBoard {
	return &HttpBoard{
		index:  index,
		client: client,
		peers:  peers,
		deals:  make(chan pedersen_dkg.DealBundle, 3),
		resps:  make(chan pedersen_dkg.ResponseBundle, 3),
		justs:  make(chan pedersen_dkg.JustificationBundle, 3),
	}
}

func (b *HttpBoard) PushDeals(deal *pedersen_dkg.DealBundle) {
	log.Printf("Pushing deal to peers\n")

	for index, peer := range b.peers {
		if index == int(b.index) {
			b.deals <- *deal
			continue
		}
		b.pushDeal(peer, deal)
	}
}

func (b *HttpBoard) pushDeal(peer string, bundle *pedersen_dkg.DealBundle) {
	url := peer + "/deals"

	// Convert deal bundle to JSON
	dealBytes, err := DealBundleToJSON(bundle)
	if err != nil {
		log.Printf("failed to encode deal bundle: %s\n", err)
		return
	}

	buf := bytes.NewBuffer(dealBytes)

	resp, err := http.Post(url, "application/json", buf)
	if err != nil {
		log.Printf("failed to send HTTP request: %s\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		buf.Reset()
		if _, err := io.Copy(buf, resp.Body); err != nil {
			log.Printf("failed to read response body: %s\n", err)
			return
		}
		log.Printf("received non-OK response: %s | %d\n", buf.String(), resp.StatusCode)
		return
	}
}

func (b *HttpBoard) IncomingDeal() <-chan pedersen_dkg.DealBundle {
	return b.deals
}

func (b *HttpBoard) PushResponses(resp *pedersen_dkg.ResponseBundle) {
	log.Printf("Pushing response to peers\n")

	for index, peer := range b.peers {
		if index == int(b.index) {
			b.resps <- *resp
			continue
		}
		b.pushResponse(peer, resp)
	}
}

func (b *HttpBoard) pushResponse(peer string, bundle *pedersen_dkg.ResponseBundle) {
	url := peer + "/responses"

	// Convert response bundle to JSON
	respBytes, err := ResponseBundleToJSON(bundle)
	if err != nil {
		log.Printf("failed to encode response bundle: %s\n", err)
		return
	}

	buf := bytes.NewBuffer(respBytes)

	resp, err := http.Post(url, "application/json", buf)
	if err != nil {
		log.Printf("failed to send HTTP request: %s\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		buf.Reset()
		if _, err := io.Copy(buf, resp.Body); err != nil {
			log.Printf("failed to read response body: %s\n", err)
			return
		}
		log.Printf("received non-OK response: %s | %d\n", buf.String(), resp.StatusCode)
		return
	}
}

func (b *HttpBoard) IncomingResponse() <-chan pedersen_dkg.ResponseBundle {
	return b.resps
}

func (b *HttpBoard) PushJustifications(bundle *pedersen_dkg.JustificationBundle) {
	log.Printf("Pushing justification to peers\n")

	for index, peer := range b.peers {
		if index == int(b.index) {
			b.justs <- *bundle
			continue
		}
		b.pushJustification(peer, bundle)
	}
}

func (b *HttpBoard) pushJustification(peer string, bundle *pedersen_dkg.JustificationBundle) {
	url := peer + "/justifications"

	// Convert justification bundle to JSON
	justBytes, err := JustificationBundleToJSON(bundle)
	if err != nil {
		log.Printf("failed to encode justification bundle: %s\n", err)
		return
	}

	buf := bytes.NewBuffer(justBytes)

	resp, err := http.Post(url, "application/json", buf)
	if err != nil {
		log.Printf("failed to send HTTP request: %s\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		buf.Reset()
		if _, err := io.Copy(buf, resp.Body); err != nil {
			log.Printf("failed to read response body: %s\n", err)
			return
		}
		log.Printf("received non-OK response: %s | %d\n", buf.String(), resp.StatusCode)
		return
	}
}

func (b *HttpBoard) IncomingJustification() <-chan pedersen_dkg.JustificationBundle {
	return b.justs
}

func (b *HttpBoard) ReceiveDealBundle(bundle pedersen_dkg.DealBundle) {
	// Send deal bundle to the specified peer
	b.deals <- bundle
}

func (b *HttpBoard) ReceiveResponseBundle(bundle pedersen_dkg.ResponseBundle) {
	// Send response bundle to the specified peer
	b.resps <- bundle
}

func (b *HttpBoard) ReceiveJustificationBundle(bundle pedersen_dkg.JustificationBundle) {
	// Send justification bundle to the specified peer
	b.justs <- bundle
}
