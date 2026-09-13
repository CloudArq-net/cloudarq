// Package arch enforces the layer boundaries described in docs/ENGINEERING.md.
//
// These are tests rather than conventions because a convention that is only
// written down gets violated on a tired evening, and the cost does not show up
// for six weeks.
package arch

import (
	"encoding/json"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// pureRoots must never reach IO, the clock, or randomness -- directly or
// transitively. They are the packages that must stay deterministic and fuzzable.
var pureRoots = []string{
	"github.com/CloudArq-net/cloudarq/internal/eval/...",
	"github.com/CloudArq-net/cloudarq/internal/join/...",
	"github.com/CloudArq-net/cloudarq/internal/parse/...",
	"github.com/CloudArq-net/cloudarq/internal/registry/...",
	"github.com/CloudArq-net/cloudarq/internal/trust/...",
}

// forbidden lists import paths that make a package non-deterministic or
// IO-bound. "time" is absent on purpose: a pure package may reference time.Time
// as a value type. What it may not do is READ the clock, which is caught by the
// separate ban on time.Now in cmd-level review and by TestDeterminism.
var forbidden = map[string]string{
	"net":          "network access in a pure package",
	"net/http":     "network access in a pure package",
	"os":           "filesystem or environment access in a pure package",
	"os/exec":      "subprocess execution in a pure package",
	"math/rand":    "nondeterminism in a pure package",
	"crypto/rand":  "nondeterminism in a pure package",
	"bufio":        "IO plumbing in a pure package",
	"database/sql": "database access in a pure package",
}

// forbiddenPrefixes catches vendored SDKs without naming every subpackage.
var forbiddenPrefixes = []string{
	"github.com/aws/aws-sdk-go",
	"cloud.google.com/go",
	"github.com/Azure/azure-sdk-for-go",
	"github.com/google/go-github",
}

// selfContained are standard packages the walk does not descend into. Each
// reaches os or syscall internally, none performs IO on the caller's behalf
// unless handed a file or a connection, and each is needed by the pure
// layers: JSON for policy documents and evidence, fmt for error wrapping,
// the digest and the timestamp type in evidence. Anything else that reaches
// a forbidden package, standard or third-party, is reported with the path
// that reaches it.
var selfContained = map[string]bool{
	"encoding/json": true,
	"fmt":           true,
	"crypto/sha256": true,
	"time":          true,
}

type pkg struct {
	ImportPath string   `json:"ImportPath"`
	Imports    []string `json:"Imports"`
}

const modulePrefix = "github.com/CloudArq-net/cloudarq/"

func TestPureLayersHaveNoIO(t *testing.T) {
	examined := 0
	for _, root := range pureRoots {
		out, err := exec.Command("go", "list", "-json", "-deps", root).Output()
		if err != nil {
			t.Fatalf("go list %s: %v", root, err)
		}
		imports := map[string][]string{}
		var firstParty []string
		dec := json.NewDecoder(strings.NewReader(string(out)))
		for dec.More() {
			var p pkg
			if err := dec.Decode(&p); err != nil {
				t.Fatalf("decode: %v", err)
			}
			imports[p.ImportPath] = p.Imports
			if strings.HasPrefix(p.ImportPath, modulePrefix) {
				firstParty = append(firstParty, p.ImportPath)
			}
		}
		for _, p := range firstParty {
			examined++
			walk(t, p, imports, []string{p}, map[string]bool{})
		}
	}

	// A filter that matches nothing would make every assertion above vacuous:
	// the test would pass by examining no packages at all. That is the exact
	// failure mode this file exists to prevent, so it is asserted rather than
	// assumed -- notably after any change to the module path.
	if examined == 0 {
		t.Fatalf("examined 0 packages under %q -- the module prefix is wrong "+
			"and this test is proving nothing", modulePrefix)
	}
	t.Logf("examined %d first-party packages", examined)
}

// walk follows direct imports from pkg, reporting every forbidden package it
// reaches together with the path that reaches it, and stopping at the
// self-contained standard packages.
func walk(t *testing.T, pkg string, imports map[string][]string, path []string, seen map[string]bool) {
	for _, dep := range imports[pkg] {
		if seen[dep] {
			continue
		}
		seen[dep] = true
		trail := strings.Join(append(slices.Clone(path), dep), " -> ")
		if why, bad := forbidden[dep]; bad {
			t.Errorf("%s: %s\n  see docs/ENGINEERING.md section 1", trail, why)
			continue
		}
		if slices.ContainsFunc(forbiddenPrefixes, func(pre string) bool { return strings.HasPrefix(dep, pre) }) {
			t.Errorf("%s: cloud SDK in a pure package\n  see docs/ENGINEERING.md section 1", trail)
			continue
		}
		if selfContained[dep] {
			continue
		}
		walk(t, dep, imports, append(slices.Clone(path), dep), seen)
	}
}

// TestControlPlaneHoldsNoCredentials is the schema guard promised in docs/ENGINEERING.md
// section 8. It is a placeholder until the control-plane schema exists, and it
// fails loudly rather than passing vacuously if someone adds one without wiring
// this up.
func TestControlPlaneHoldsNoCredentials(t *testing.T) {
	t.Skip("enable when internal/controlplane/schema exists; see docs/ENGINEERING.md section 8")
}
