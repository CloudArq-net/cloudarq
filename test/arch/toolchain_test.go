package arch

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEveryWorkflowInstallsTheGoTheModulePins: go.mod's toolchain line names
// the Go the checks run on, and every setup-go step in every workflow
// installs exactly that Go, so what CI tests is what a default build
// compiles, and a release file is built by the Go its checks ran on. A
// go-version that resolves to the newest patch of a line, one read from a
// file, or one go.mod does not name tests or builds an engine nobody
// checked.
func TestEveryWorkflowInstallsTheGoTheModulePins(t *testing.T) {
	toolchain := toolchainOf(t)
	paths := workflowPaths(t)
	var steps, versions int
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		s, v, found := checkGoVersions(string(raw), toolchain)
		steps += s
		versions += v
		for _, f := range found {
			t.Errorf("%s:%s", filepath.Base(path), f)
		}
	}
	if steps == 0 || versions == 0 {
		t.Fatalf("%d setup-go steps and %d go-version lines in %d workflows; this test examined nothing", steps, versions, len(paths))
	}
	t.Logf("go%s, in go.mod and in %d go-version lines of %d setup-go steps in %d workflows", toolchain, versions, steps, len(paths))
}

// toolchainOf is the version go.mod's toolchain line names, without "go".
func toolchainOf(t *testing.T) string {
	t.Helper()
	mod, err := os.ReadFile(filepath.Join(moduleRoot(t), "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	toolchain := regexp.MustCompile(`(?m)^toolchain go(\S+)$`).FindSubmatch(mod)
	if toolchain == nil {
		t.Fatalf("go.mod has no toolchain line; it names the Go the checks run on")
	}
	return string(toolchain[1])
}

var (
	goVersionLine = regexp.MustCompile(`^(?:-\s+)?go-version:\s*(.*)$`)
	goVersionFile = regexp.MustCompile(`^(?:-\s+)?go-version-file:`)
)

// checkGoVersions reads the Go one workflow installs: every go-version must
// be toolchain, no go-version-file may stand in for one, and every setup-go
// step must name one under its with:. It returns how many setup-go steps and
// go-version lines it read.
func checkGoVersions(text, toolchain string) (steps, versions int, found []violation) {
	lines, unread := structure(text)
	found = append(found, unread...)
	for i, l := range lines {
		if goVersionFile.MatchString(l.text) {
			found = append(found, violation{l.n, ruleGoVersion,
				fmt.Sprintf("go-version-file reads the Go from a file; name go-version: '%s'", toolchain)})
		}
		if m := goVersionLine.FindStringSubmatch(l.text); m != nil {
			versions++
			if v := unquote(m[1]); v != toolchain {
				found = append(found, violation{l.n, ruleGoVersion, fmt.Sprintf("installs Go %s; go.mod pins go%s", v, toolchain)})
			}
		}
		m := usesLine.FindStringSubmatch(l.text)
		if m == nil || !strings.HasPrefix(unquote(m[1]), "actions/setup-go@") {
			continue
		}
		steps++
		if !withSets(lines, i, goVersionLine) {
			found = append(found, violation{l.n, ruleGoVersion, "this setup-go step names no go-version under its with:"})
		}
	}
	return steps, versions, found
}
