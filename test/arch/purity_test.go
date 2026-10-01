// Package arch holds the module to its structure: the pure packages reach
// no IO, letter case is folded from the module's own tables, CI installs the
// Go the module pins, and the workflows pin their actions.
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

// pureRoots must never reach IO, a system call or randomness, directly or
// through another package. They are the packages that must stay
// deterministic and fuzzable.
var pureRoots = []string{
	"github.com/CloudArq-net/cloudarq/internal/eval/...",
	"github.com/CloudArq-net/cloudarq/internal/join/...",
	"github.com/CloudArq-net/cloudarq/internal/parse/...",
	"github.com/CloudArq-net/cloudarq/internal/registry/...",
	"github.com/CloudArq-net/cloudarq/internal/report/...",
	"github.com/CloudArq-net/cloudarq/internal/ring/...",
	"github.com/CloudArq-net/cloudarq/internal/trust/...",
}

// forbidden lists import paths that make a package non-deterministic or
// IO-bound. "time" is absent on purpose: a pure package may reference time.Time
// as a value type. What it may not do is READ the clock: none of them calls
// time.Now, and output that depended on the clock would fail TestDeterminism.
var forbidden = map[string]string{
	"net":          "network access in a pure package",
	"net/http":     "network access in a pure package",
	"os":           "filesystem or environment access in a pure package",
	"os/exec":      "subprocess execution in a pure package",
	"syscall":      "system calls in a pure package",
	"math/rand":    "nondeterminism in a pure package",
	"math/rand/v2": "nondeterminism in a pure package",
	"crypto/rand":  "nondeterminism in a pure package",
	"hash/maphash": "a per-process random seed in a pure package",
	"bufio":        "IO plumbing in a pure package",
	"database/sql": "database access in a pure package",
}

// forbiddenPrefixes catches vendored SDKs and the system-call packages
// outside the standard library without naming every subpackage.
var forbiddenPrefixes = []string{
	"github.com/aws/aws-sdk-go",
	"cloud.google.com/go",
	"github.com/Azure/azure-sdk-for-go",
	"github.com/google/go-github",
	"golang.org/x/sys",
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
			for _, v := range reached(p, imports, []string{p}, map[string]bool{}) {
				t.Errorf("%s\n  a pure package reaches no IO; see docs/OVERVIEW.md", v)
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

// reached follows direct imports from pkg and returns every forbidden
// package it reaches, each with the path that reaches it and why it is
// forbidden, stopping at the self-contained standard packages.
func reached(pkg string, imports map[string][]string, path []string, seen map[string]bool) []string {
	var found []string
	for _, dep := range imports[pkg] {
		if seen[dep] {
			continue
		}
		seen[dep] = true
		trail := strings.Join(append(slices.Clone(path), dep), " -> ")
		if why, bad := forbidden[dep]; bad {
			found = append(found, trail+": "+why)
			continue
		}
		if slices.ContainsFunc(forbiddenPrefixes, func(pre string) bool { return strings.HasPrefix(dep, pre) }) {
			found = append(found, trail+": a cloud SDK or system calls in a pure package")
			continue
		}
		if selfContained[dep] {
			continue
		}
		found = append(found, reached(dep, imports, append(slices.Clone(path), dep), seen)...)
	}
	return found
}

// TestTheGateRefusesEachWayOut: a package importing any of these, directly
// or through a standard package the walk descends into, is reported. The
// list is the network, the filesystem and the environment, subprocesses,
// raw system calls, and every source of randomness the standard library
// and golang.org/x/sys offer; the self-contained packages are where the
// walk stops, and nothing else.
func TestTheGateRefusesEachWayOut(t *testing.T) {
	ways := []string{
		"net", "net/http", "os", "os/exec", "syscall", "golang.org/x/sys/unix",
		"math/rand", "math/rand/v2", "crypto/rand", "hash/maphash",
		"bufio", "database/sql", "github.com/aws/aws-sdk-go-v2/service/sts",
	}
	for _, way := range ways {
		direct := map[string][]string{"probe": {way}}
		if got := reached("probe", direct, []string{"probe"}, map[string]bool{}); len(got) != 1 {
			t.Errorf("a pure package importing %s: reported %q, want it reported once", way, got)
		}
		through := map[string][]string{"probe": {"strings"}, "strings": {way}}
		if got := reached("probe", through, []string{"probe"}, map[string]bool{}); len(got) != 1 || !strings.Contains(got[0], "probe -> strings -> "+way) {
			t.Errorf("a pure package reaching %s through strings: reported %q, want the path", way, got)
		}
	}
	for stop := range selfContained {
		behind := map[string][]string{"probe": {stop}, stop: {"os"}}
		if got := reached("probe", behind, []string{"probe"}, map[string]bool{}); len(got) != 0 {
			t.Errorf("%s is where the walk stops, and it reported %q", stop, got)
		}
	}
}
