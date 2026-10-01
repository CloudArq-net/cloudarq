package arch

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestWorkflowsArePinnedAndHoldNoCredentials reads every workflow under
// .github/workflows and holds three things a pull request could otherwise
// loosen without anyone reading the YAML closely:
//
//   - the workflow grants its token nothing (permissions: {} at the top), so
//     a compromised step has no write access to the repository;
//   - every action is pinned to a full commit SHA, because a tag can be
//     moved to other code after it was reviewed;
//   - every checkout sets persist-credentials: false, so the token is not
//     left in .git/config for the steps that follow to read.
func TestWorkflowsArePinnedAndHoldNoCredentials(t *testing.T) {
	gomod, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil || strings.TrimSpace(string(gomod)) == "" {
		t.Fatalf("go env GOMOD: %q, %v", gomod, err)
	}
	root := filepath.Dir(strings.TrimSpace(string(gomod)))
	paths, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no workflow under .github/workflows; this test examined nothing")
	}
	var actions, checkouts int
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(path)
		a, c := checkWorkflow(t, name, string(raw))
		actions += a
		checkouts += c
	}
	if actions == 0 || checkouts == 0 {
		t.Fatalf("%d actions and %d checkouts in %d workflows; this test examined too little", actions, checkouts, len(paths))
	}
	t.Logf("read %d workflows, %d actions and %d checkouts", len(paths), actions, checkouts)
}

var (
	topPermissions = regexp.MustCompile(`^permissions:\s*(.*?)\s*$`)
	usesLine       = regexp.MustCompile(`^(\s*)(?:-\s+)?uses:\s*(\S+)`)
	pinned         = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$`)
	persistOff     = regexp.MustCompile(`^\s*persist-credentials:\s*false\s*$`)
	stepStart      = regexp.MustCompile(`^(\s*)-\s`)
)

// checkWorkflow reports each rule the workflow breaks, and how many actions
// and checkouts it read.
func checkWorkflow(t *testing.T, name, text string) (actions, checkouts int) {
	t.Helper()
	lines := strings.Split(text, "\n")
	var grants []string
	for _, line := range lines {
		if m := topPermissions.FindStringSubmatch(line); m != nil {
			grants = append(grants, m[1])
		}
	}
	if len(grants) != 1 || grants[0] != "{}" {
		t.Errorf("%s: the top-level permissions are %q; want exactly one line, permissions: {}", name, grants)
	}
	for i, line := range lines {
		m := usesLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		actions++
		if !pinned.MatchString(m[2]) {
			t.Errorf("%s:%d: %s is not pinned to a full commit SHA", name, i+1, m[2])
		}
		if !strings.HasPrefix(m[2], "actions/checkout@") {
			continue
		}
		checkouts++
		if !stepSets(lines, i, persistOff) {
			t.Errorf("%s:%d: this checkout does not set persist-credentials: false", name, i+1)
		}
	}
	return actions, checkouts
}

// stepSets reports whether the step that holds line i has a line matching
// want: the step runs from its "- " line to the next line at the same or a
// shallower indentation.
func stepSets(lines []string, i int, want *regexp.Regexp) bool {
	start, indent := i, -1
	for ; start >= 0; start-- {
		if m := stepStart.FindStringSubmatch(lines[start]); m != nil {
			indent = len(m[1])
			break
		}
	}
	if indent < 0 {
		return false
	}
	for j := start; j < len(lines); j++ {
		if j > start {
			trimmed := strings.TrimLeft(lines[j], " ")
			if trimmed != "" && len(lines[j])-len(trimmed) <= indent {
				break
			}
		}
		if want.MatchString(lines[j]) {
			return true
		}
	}
	return false
}
