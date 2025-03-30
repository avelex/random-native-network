package dkg

import (
	"encoding/hex"

	"go.dedis.ch/kyber/v4"
	pedersen_dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
)

const Threshold = 2

var Nodes = []pedersen_dkg.Node{
	{
		Index:  0,
		Public: mustPubKeyFromHex("89fcba2df44725c8753d75e3bd994abfa043e3021f9eb0a8fe75823c263274f261283f50affb44471f9b3be093bc083afc680c8bc946f21bb5d2cc67bc134a6d4d65eb7d570fd4abc084c066a307efd4393ef68d27b6c6b010d1abecfcef6c4a67b1d25cedefbcfe3348973c1664f4927e0547ce1252d4b1065264064d671ea7"),
	},
	{
		Index:  1,
		Public: mustPubKeyFromHex("7b1d09b547bf1de9999b40d7d56d011876482c719e84ab3d124473df7731af1925b33d8de8844993570edfa497dc9bf40e2cf648f01c764bd57069b6519340ef773c01f966ffb51bd4f7ef86d89277dc09efeb889fff16688f0eca43d9bdc44e7936abe52cc4e16146412bbde60a83a84dd221ae4b51ad4589851aaf5d4f5e81"),
	},
	{
		Index:  2,
		Public: mustPubKeyFromHex("880565f2fbc96ae5d60c1545ed00b98bf841426655183c224b55da482121111d72332ba036df07e2a0dcf2e3e96bdff628dc7ff7bba5285996d2e54d2709c91e407ff096dc1bd1d430edc35f2d45cfbb45ab56beb9347ddc48e753d7fc6b81313bd32247f5a4a86865fe9f6499869fbc8f57c7d5cd74eb4542025a2ddbbc0640"),
	},
}

func mustPubKeyFromHex(hexStr string) kyber.Point {
	pubBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(err)
	}
	point := Suite.Point()
	if err := point.UnmarshalBinary(pubBytes); err != nil {
		panic(err)
	}
	return point
}
