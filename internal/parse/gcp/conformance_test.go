package gcp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// grantsDir holds the triples: one logical grant written in every
// provider's syntax. Loaded by tests only; the package reads no files.
const grantsDir = "../../../testdata/grants"

// gcpDocuments loads the GCP document of every case GCP can express, the
// way internal/trust's own tests do.
func gcpDocuments(t *testing.T) map[string][]byte {
	t.Helper()
	documents := map[string][]byte{}
	for _, c := range trust.Cases() {
		if _, no := c.Inexpressible[trust.GCP]; no {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(grantsDir, c.Name, "gcp.json"))
		if err != nil {
			t.Fatalf("%v", err)
		}
		documents[c.Name] = raw
	}
	if len(documents) == 0 {
		t.Fatalf("no GCP document under %s; the harness would examine nothing", grantsDir)
	}
	return documents
}

// gcpParser is the package registered with the cross-provider harness: one
// document, one provider, one Grant.
func gcpParser(document []byte) ([]trust.Grant, error) {
	p, err := ParseProvider(document)
	if err != nil {
		return nil, err
	}
	return p.Grants(githubProvider), nil
}

// TestConformance: every case the triples state, this parser states the
// same way, judged by the neutral harness rather than by this package's
// own expectations.
func TestConformance(t *testing.T) {
	documents := gcpDocuments(t)
	failures := trust.Check(trust.GCP, gcpParser, documents)
	for _, f := range failures {
		t.Errorf("%v", f)
	}
	expressible := 0
	for _, c := range trust.Cases() {
		if _, no := c.Inexpressible[trust.GCP]; !no {
			expressible++
		}
	}
	if len(documents) != expressible {
		t.Errorf("examined %d documents, want one per expressible case (%d)", len(documents), expressible)
	}
	t.Logf("examined %d documents, %d failures", len(documents), len(failures))
}

// TestConformanceBites: the harness must reject this parser's output once
// it is bent, or a pass above would prove nothing about the parser.
func TestConformanceBites(t *testing.T) {
	documents := gcpDocuments(t)
	narrowed := func(document []byte) ([]trust.Grant, error) {
		grants, err := gcpParser(document)
		if err != nil {
			return nil, err
		}
		grants[0].Admits = eval.NewAdmittedSet(eval.Term{"sub": eval.Exact(mainBranch), "aud": eval.Exact(audienceName)})
		return grants, nil
	}
	failures := trust.Check(trust.GCP, narrowed, documents)
	if len(failures) != len(documents)-1 {
		t.Errorf("a parser pinned to one branch must fail every case but the one that is one branch; got %d failures: %v", len(failures), failures)
	}
	caveated := func(document []byte) ([]trust.Grant, error) {
		grants, err := gcpParser(document)
		if err != nil {
			return nil, err
		}
		grants[0].Admits = grants[0].Admits.WithCaveat(eval.Caveat{Claim: "sub", Reason: "invented", Source: "test"})
		return grants, nil
	}
	if failures := trust.Check(trust.GCP, caveated, documents); len(failures) != len(documents) {
		t.Errorf("a caveat on an exact case must fail every case; got %v", failures)
	}
}
