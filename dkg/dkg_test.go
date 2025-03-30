package dkg

import (
	"errors"
	"fmt"
	"testing"

	clock "github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing/bn256"
	"go.dedis.ch/kyber/v4/share"
	pedersen_dkg "go.dedis.ch/kyber/v4/share/dkg/pedersen"
	"go.dedis.ch/kyber/v4/sign/schnorr"
	"go.dedis.ch/kyber/v4/sign/tbls"
	"go.dedis.ch/kyber/v4/util/random"
)

type TestNode struct {
	Index   uint32
	Private kyber.Scalar
	Public  kyber.Point
	dkg     *pedersen_dkg.DistKeyGenerator
	res     *pedersen_dkg.Result
	proto   *pedersen_dkg.Protocol
	phaser  *pedersen_dkg.TimePhaser
	board   *TestBoard
	clock   clock.FakeClock
}

type TestBoard struct {
	index    uint32
	newDeals chan pedersen_dkg.DealBundle
	newResps chan pedersen_dkg.ResponseBundle
	newJusts chan pedersen_dkg.JustificationBundle
	network  *TestNetwork
	badDeal  bool
	badSig   bool
}

type TestNetwork struct {
	boards []*TestBoard
	noops  []uint32
}

func NewTestNode(s pedersen_dkg.Suite, index int) *TestNode {
	private := s.Scalar().Pick(random.New())
	public := s.Point().Mul(private, nil)
	return &TestNode{
		Index:   uint32(index),
		Private: private,
		Public:  public,
	}
}

func GenerateTestNodes(s pedersen_dkg.Suite, n int) []*TestNode {
	tns := make([]*TestNode, n)
	for i := 0; i < n; i++ {
		tns[i] = NewTestNode(s, i)
	}
	return tns
}

func NodesFromTest(tns []*TestNode) []pedersen_dkg.Node {
	nodes := make([]pedersen_dkg.Node, len(tns))
	for i := 0; i < len(tns); i++ {
		nodes[i] = pedersen_dkg.Node{
			Index:  tns[i].Index,
			Public: tns[i].Public,
		}
	}
	return nodes
}

// inits the dkg structure
func SetupNodes(nodes []*TestNode, c *pedersen_dkg.Config) {
	nonce := pedersen_dkg.GetNonce()
	for _, n := range nodes {
		c2 := *c
		c2.Longterm = n.Private
		c2.Nonce = nonce
		dkg, err := pedersen_dkg.NewDistKeyHandler(&c2)
		if err != nil {
			panic(err)
		}
		n.dkg = dkg
	}
}

func testResults(t *testing.T, suite pedersen_dkg.Suite, thr, n int, results []*pedersen_dkg.Result) {
	// test if all results are consistent
	for i, res := range results {
		require.Equal(t, thr, len(res.Key.Commitments()))
		for j, res2 := range results {
			if i == j {
				continue
			}
			require.True(t, res.PublicEqual(res2), "res %+v != %+v", res, res2)
		}
	}
	// test if re-creating secret key gives same public key
	var shares []*share.PriShare
	for _, res := range results {
		shares = append(shares, res.Key.PriShare())
	}
	// test if shares are public polynomial evaluation
	exp := share.NewPubPoly(suite, suite.Point().Base(), results[0].Key.Commitments())
	for _, share := range shares {
		pubShare := exp.Eval(share.I)
		expShare := suite.Point().Mul(share.V, nil)
		require.True(t, pubShare.V.Equal(expShare), "share %s give pub %s vs exp %s", share.V.String(), pubShare.V.String(), expShare.String())
	}

	secretPoly, err := share.RecoverPriPoly(suite, shares, thr, n)
	require.NoError(t, err)
	gotPub := secretPoly.Commit(suite.Point().Base())
	require.True(t, exp.Equal(gotPub))

	secret, err := share.RecoverSecret(suite, shares, thr, n)
	require.NoError(t, err)
	public := suite.Point().Mul(secret, nil)
	expKey := results[0].Key.Public()
	require.True(t, public.Equal(expKey))

}

type MapDeal func([]*pedersen_dkg.DealBundle) []*pedersen_dkg.DealBundle
type MapResponse func([]*pedersen_dkg.ResponseBundle) []*pedersen_dkg.ResponseBundle
type MapJustif func([]*pedersen_dkg.JustificationBundle) []*pedersen_dkg.JustificationBundle

func RunDKG(t *testing.T, tns []*TestNode, conf pedersen_dkg.Config,
	dm MapDeal, rm MapResponse, jm MapJustif) []*pedersen_dkg.Result {

	SetupNodes(tns, &conf)

	var deals []*pedersen_dkg.DealBundle

	for _, node := range tns {
		d, err := node.dkg.Deals()
		require.NoError(t, err)
		deals = append(deals, d)
	}

	if dm != nil {
		deals = dm(deals)
	}

	var respBundles []*pedersen_dkg.ResponseBundle
	for _, node := range tns {
		resp, err := node.dkg.ProcessDeals(deals)
		require.NoError(t, err)
		if resp != nil {
			respBundles = append(respBundles, resp)
		}
	}

	if rm != nil {
		respBundles = rm(respBundles)
	}

	fmt.Printf("respBundles: %v\n", len(respBundles))

	var justifs []*pedersen_dkg.JustificationBundle
	var results []*pedersen_dkg.Result

	for _, node := range tns {
		res, just, err := node.dkg.ProcessResponses(respBundles)
		if !errors.Is(err, pedersen_dkg.ErrEvicted) {
			// there should not be any other error than eviction
			require.NoError(t, err)
		}
		if res != nil {
			results = append(results, res)
		} else if just != nil {
			justifs = append(justifs, just)
		}
	}

	if len(justifs) == 0 {
		return results
	}

	if jm != nil {
		justifs = jm(justifs)
	}

	for _, node := range tns {
		res, err := node.dkg.ProcessJustifications(justifs)
		if errors.Is(err, pedersen_dkg.ErrEvicted) {
			continue
		}
		require.NoError(t, err)
		require.NotNil(t, res)
		results = append(results, res)
	}
	return results
}

func TestSelfEvictionShareHolder(t *testing.T) {
	n := 3
	threshold := 2

	var suite = bn256.NewSuiteG2()
	var sigSuite = bn256.NewSuiteG1()

	tns := GenerateTestNodes(suite, n)
	list := NodesFromTest(tns)

	conf := pedersen_dkg.Config{
		Suite:     suite,
		NewNodes:  list,
		Threshold: threshold,
		Auth:      schnorr.NewScheme(suite),
	}

	results := RunDKG(t, tns, conf, nil, nil, nil)
	for i, t := range tns {
		t.res = results[i]
	}

	testResults(t, suite, threshold, n, results)

	// create a partial signature with the share now and make sure the partial
	// signature is verifiable and then *not* verifiable after the resharing
	oldShare := results[0].Key.Share
	//second := results[0].Key.Share
	msg := []byte("Hello World")
	scheme := tbls.NewThresholdSchemeOnG1(sigSuite)
	oldPartial, err := scheme.Sign(oldShare, msg)
	require.NoError(t, err)
	poly := share.NewPubPoly(suite, suite.Point().Base(), results[0].Key.Commits)

	require.NoError(t, scheme.VerifyPartial(poly, msg, oldPartial))

	sigShares := make([][]byte, 0)

	sig1, err := scheme.Sign(results[0].Key.Share, msg)
	require.NoError(t, err)

	sig2, err := scheme.Sign(results[1].Key.Share, msg)
	require.NoError(t, err)

	sigShares = append(sigShares, sig1, sig2)

	sig, err := scheme.Recover(poly, msg, sigShares, threshold, n)
	require.NoError(t, err)

	require.NoError(t, scheme.VerifyRecovered(poly.Commit(), msg, sig))
}
