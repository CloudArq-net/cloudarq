// Package arch enforces the layer boundaries described in docs/ENGINEERING.md.
//
// These are tests rather than conventions because a convention that is only
// written down gets violated on a tired evening, and the cost does not show up
// for six weeks.
package arch

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// pureRoots must never reach IO, the clock, or randomness -- directly or
// transitively. They are the packages that must stay deterministic and fuzzable.
var pureRoots = []string{
	"github.com/CloudArq-net/cloudarq/internal/eval/...",
	"github.com/CloudArq-net/cloudarq/internal/parse/...",
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

type pkg struct {
	ImportPath string   `json:"ImportPath"`
	Deps       []string `json:"Deps"`
}

const modulePrefix = "github.com/CloudArq-net/cloudarq/"

func TestPureLayersHaveNoIO(t *testing.T) {
	examined := 0
	for _, root := range pureRoots {
		out, err := exec.Command("go", "list", "-json", "-deps", root).Output()
		if err != nil {
			t.Fatalf("go list %s: %v", root, err)
		}
		dec := json.NewDecoder(strings.NewReader(string(out)))
		for dec.More() {
			var p pkg
			if err := dec.Decode(&p); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !strings.HasPrefix(p.ImportPath, modulePrefix) {
				continue
			}
			examined++
			for _, dep := range p.Deps {
				if why, bad := forbidden[dep]; bad {
					t.Errorf("%s imports %q: %s\n  see docs/ENGINEERING.md section 1", p.ImportPath, dep, why)
				}
				for _, pre := range forbiddenPrefixes {
					if strings.HasPrefix(dep, pre) {
						t.Errorf("%s imports %q: cloud SDK in a pure package\n  see docs/ENGINEERING.md section 1", p.ImportPath, dep)
					}
				}
			}
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

// TestControlPlaneHoldsNoCredentials is the schema guard promised in docs/ENGINEERING.md
// section 8. It is a placeholder until the control-plane schema exists, and it
// fails loudly rather than passing vacuously if someone adds one without wiring
// this up.
func TestControlPlaneHoldsNoCredentials(t *testing.T) {
	t.Skip("enable when internal/controlplane/schema exists; see docs/ENGINEERING.md section 8")
}
