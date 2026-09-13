package aws

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// grantsDir holds the triples: the same logical grant in every provider's
// syntax. The AWS documents are what this parser is judged against.
const grantsDir = "../../../testdata/grants"

// TestConformance registers the parser with the trust harness over every
// case AWS can express. The harness judges canonical equality with the
// expected set, demands a caveat for every Unknown and an anomaly for the
// one case AWS can state that the other providers cannot, and refuses to
// pass on a missing document.
func TestConformance(t *testing.T) {
	documents := map[string][]byte{}
	for _, c := range trust.Cases() {
		if _, no := c.Inexpressible[trust.AWS]; no {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(grantsDir, c.Name, "aws.json"))
		if err != nil {
			t.Fatalf("%v", err)
		}
		documents[c.Name] = raw
	}
	if len(documents) == 0 {
		t.Fatalf("no documents; the harness would examine nothing")
	}
	parser := func(document []byte) ([]trust.Grant, error) {
		d, err := ParseTrustPolicy(document)
		if err != nil {
			return nil, err
		}
		return d.Grants(role, vocabulary), nil
	}
	failures := trust.Check(trust.AWS, parser, documents)
	for _, f := range failures {
		t.Errorf("%v", f)
	}
	t.Logf("examined %d documents, %d failures", len(documents), len(failures))
}
