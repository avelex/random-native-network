package dkg

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	pedersen_dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
)

// DealBundleDTO is a Data Transfer Object for pedersen_dkg.DealBundle
// with JSON tags for serialization
type DealBundleDTO struct {
	DealerIndex uint32    `json:"dealerIndex"`
	Deals       []DealDTO `json:"deals"`
	Public      []string  `json:"public"`
	SessionID   string    `json:"sessionId"`
	Signature   string    `json:"signature"`
}

// DealDTO is a Data Transfer Object for pedersen_dkg.Deal
type DealDTO struct {
	ShareIndex     uint32 `json:"shareIndex"`
	EncryptedShare string `json:"encryptedShare"`
}

// ResponseBundleDTO is a Data Transfer Object for pedersen_dkg.ResponseBundle
type ResponseBundleDTO struct {
	ShareIndex uint32        `json:"shareIndex"`
	Responses  []ResponseDTO `json:"responses"`
	SessionID  string        `json:"sessionId"`
	Signature  string        `json:"signature"`
}

// ResponseDTO is a Data Transfer Object for pedersen_dkg.Response
type ResponseDTO struct {
	DealerIndex uint32 `json:"dealerIndex"`
	Status      int32  `json:"status"`
}

// JustificationBundleDTO is a Data Transfer Object for pedersen_dkg.JustificationBundle
// with JSON tags for serialization
type JustificationBundleDTO struct {
	DealerIndex    uint32             `json:"dealerIndex"`
	Justifications []JustificationDTO `json:"justifications"`
	SessionID      string             `json:"sessionId"`
	Signature      string             `json:"signature"`
}

// JustificationDTO is a Data Transfer Object for pedersen_dkg.Justification
type JustificationDTO struct {
	ShareIndex uint32 `json:"shareIndex"`
	Share      string `json:"share"`
}

// MarshalDealBundle converts a pedersen_dkg.DealBundle to a DealBundleDTO
func MarshalDealBundle(bundle *pedersen_dkg.DealBundle) (*DealBundleDTO, error) {
	dto := &DealBundleDTO{
		DealerIndex: bundle.DealerIndex,
		SessionID:   hex.EncodeToString(bundle.SessionID),
		Signature:   hex.EncodeToString(bundle.Signature),
	}

	// Marshal deals
	for _, deal := range bundle.Deals {
		dto.Deals = append(dto.Deals, DealDTO{
			ShareIndex:     deal.ShareIndex,
			EncryptedShare: hex.EncodeToString(deal.EncryptedShare),
		})
	}

	// Marshal public points
	for _, pub := range bundle.Public {
		pubBytes, err := pub.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public point: %w", err)
		}
		dto.Public = append(dto.Public, hex.EncodeToString(pubBytes))
	}

	return dto, nil
}

// UnmarshalDealBundle converts a DealBundleDTO to a pedersen_dkg.DealBundle
func UnmarshalDealBundle(dto *DealBundleDTO) (*pedersen_dkg.DealBundle, error) {
	bundle := &pedersen_dkg.DealBundle{
		DealerIndex: dto.DealerIndex,
	}

	// Unmarshal session ID
	sessionID, err := hex.DecodeString(dto.SessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to decode session ID: %w", err)
	}
	bundle.SessionID = sessionID

	// Unmarshal signature
	signature, err := hex.DecodeString(dto.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}
	bundle.Signature = signature

	// Unmarshal deals
	for _, dealDTO := range dto.Deals {
		encryptedShare, err := hex.DecodeString(dealDTO.EncryptedShare)
		if err != nil {
			return nil, fmt.Errorf("failed to decode encrypted share: %w", err)
		}
		bundle.Deals = append(bundle.Deals, pedersen_dkg.Deal{
			ShareIndex:     dealDTO.ShareIndex,
			EncryptedShare: encryptedShare,
		})
	}

	// Unmarshal public points
	for _, pubStr := range dto.Public {
		pubBytes, err := hex.DecodeString(pubStr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode public point: %w", err)
		}
		point := Suite.Point()
		if err := point.UnmarshalBinary(pubBytes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal public point: %w", err)
		}
		bundle.Public = append(bundle.Public, point)
	}

	return bundle, nil
}

// MarshalResponseBundle converts a pedersen_dkg.ResponseBundle to a ResponseBundleDTO
func MarshalResponseBundle(bundle *pedersen_dkg.ResponseBundle) (*ResponseBundleDTO, error) {
	dto := &ResponseBundleDTO{
		ShareIndex: bundle.ShareIndex,
		SessionID:  hex.EncodeToString(bundle.SessionID),
		Signature:  hex.EncodeToString(bundle.Signature),
	}

	// Marshal responses
	for _, resp := range bundle.Responses {
		dto.Responses = append(dto.Responses, ResponseDTO{
			DealerIndex: resp.DealerIndex,
			Status:      int32(resp.Status),
		})
	}

	return dto, nil
}

// UnmarshalResponseBundle converts a ResponseBundleDTO to a pedersen_dkg.ResponseBundle
func UnmarshalResponseBundle(dto *ResponseBundleDTO) (*pedersen_dkg.ResponseBundle, error) {
	bundle := &pedersen_dkg.ResponseBundle{
		ShareIndex: dto.ShareIndex,
	}

	// Unmarshal session ID
	sessionID, err := hex.DecodeString(dto.SessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to decode session ID: %w", err)
	}
	bundle.SessionID = sessionID

	// Unmarshal signature
	signature, err := hex.DecodeString(dto.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}
	bundle.Signature = signature

	// Unmarshal responses
	for _, respDTO := range dto.Responses {
		bundle.Responses = append(bundle.Responses, pedersen_dkg.Response{
			DealerIndex: respDTO.DealerIndex,
			Status:      pedersen_dkg.Status(respDTO.Status),
		})
	}

	return bundle, nil
}

// DealBundleToJSON converts a pedersen_dkg.DealBundle to JSON bytes
func DealBundleToJSON(bundle *pedersen_dkg.DealBundle) ([]byte, error) {
	dto, err := MarshalDealBundle(bundle)
	if err != nil {
		return nil, err
	}
	return json.Marshal(dto)
}

// DealBundleFromJSON converts JSON bytes to a pedersen_dkg.DealBundle
func DealBundleFromJSON(data []byte) (*pedersen_dkg.DealBundle, error) {
	var dto DealBundleDTO
	if err := json.Unmarshal(data, &dto); err != nil {
		return nil, err
	}

	return UnmarshalDealBundle(&dto)
}

// ResponseBundleToJSON converts a pedersen_dkg.ResponseBundle to JSON bytes
func ResponseBundleToJSON(bundle *pedersen_dkg.ResponseBundle) ([]byte, error) {
	dto, err := MarshalResponseBundle(bundle)
	if err != nil {
		return nil, err
	}
	return json.Marshal(dto)
}

// ResponseBundleFromJSON converts JSON bytes to a pedersen_dkg.ResponseBundle
func ResponseBundleFromJSON(data []byte) (*pedersen_dkg.ResponseBundle, error) {
	var dto ResponseBundleDTO
	if err := json.Unmarshal(data, &dto); err != nil {
		return nil, err
	}

	return UnmarshalResponseBundle(&dto)
}

// JustificationBundleToJSON converts a pedersen_dkg.JustificationBundle to JSON bytes
func JustificationBundleToJSON(bundle *pedersen_dkg.JustificationBundle) ([]byte, error) {
	dto, err := MarshalJustificationBundle(bundle)
	if err != nil {
		return nil, err
	}
	return json.Marshal(dto)
}

// JustificationBundleFromJSON converts JSON bytes to a pedersen_dkg.JustificationBundle
func JustificationBundleFromJSON(data []byte) (*pedersen_dkg.JustificationBundle, error) {
	var dto JustificationBundleDTO
	if err := json.Unmarshal(data, &dto); err != nil {
		return nil, err
	}

	return UnmarshalJustificationBundle(&dto)
}

// MarshalJustificationBundle converts a pedersen_dkg.JustificationBundle to a JustificationBundleDTO
func MarshalJustificationBundle(bundle *pedersen_dkg.JustificationBundle) (*JustificationBundleDTO, error) {
	dto := &JustificationBundleDTO{
		DealerIndex:    bundle.DealerIndex,
		Justifications: make([]JustificationDTO, len(bundle.Justifications)),
		SessionID:      hex.EncodeToString(bundle.SessionID),
		Signature:      hex.EncodeToString(bundle.Signature),
	}

	for i, justification := range bundle.Justifications {
		share, err := justification.Share.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal share: %w", err)
		}
		dto.Justifications[i] = JustificationDTO{
			ShareIndex: justification.ShareIndex,
			Share:      hex.EncodeToString(share),
		}
	}

	return dto, nil
}

// UnmarshalJustificationBundle converts a JustificationBundleDTO to a pedersen_dkg.JustificationBundle
func UnmarshalJustificationBundle(dto *JustificationBundleDTO) (*pedersen_dkg.JustificationBundle, error) {
	sessionID, err := hex.DecodeString(dto.SessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to decode session ID: %w", err)
	}

	signature, err := hex.DecodeString(dto.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	bundle := &pedersen_dkg.JustificationBundle{
		DealerIndex:    dto.DealerIndex,
		Justifications: make([]pedersen_dkg.Justification, len(dto.Justifications)),
		SessionID:      sessionID,
		Signature:      signature,
	}

	for i, justificationDTO := range dto.Justifications {
		share, err := hex.DecodeString(justificationDTO.Share)
		if err != nil {
			return nil, fmt.Errorf("failed to decode share: %w", err)
		}

		scalar := Suite.Scalar()
		if err := scalar.UnmarshalBinary(share); err != nil {
			return nil, fmt.Errorf("failed to unmarshal share: %w", err)
		}

		bundle.Justifications[i] = pedersen_dkg.Justification{
			ShareIndex: justificationDTO.ShareIndex,
			Share:      scalar,
		}
	}

	return bundle, nil
}
