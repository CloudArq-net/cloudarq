package arch

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestCIInstallsTheGoTheModulePins: go.mod's toolchain line names the Go the
// checks run on, and every setup-go step in CI installs exactly that
// Go, so what CI tests is what a default build compiles. A go-version CI
// resolves to the newest patch of a line, or to one go.mod does not name,
// tests an engine nobody ships.
func TestCIInstallsTheGoTheModulePins(t *testing.T) {
	gomod, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil || strings.TrimSpace(string(gomod)) == "" {
		t.Fatalf("go env GOMOD: %q, %v", gomod, err)
	}
	root := filepath.Dir(strings.TrimSpace(string(gomod)))
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	toolchain := regexp.MustCompile(`(?m)^toolchain go(\S+)$`).FindSubmatch(mod)
	if toolchain == nil {
		t.Fatalf("go.mod has no toolchain line; it names the Go the checks run on")
	}
	ci, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	versions := regexp.MustCompile(`(?m)^\s*go-version:\s*['"]?([^'"\s]+)['"]?\s*$`).FindAllSubmatch(ci, -1)
	if len(versions) == 0 {
		t.Fatal("ci.yml installs no Go with a go-version; this test examined nothing")
	}
	for _, v := range versions {
		if string(v[1]) != string(toolchain[1]) {
			t.Errorf("ci.yml installs Go %s; go.mod pins go%s", v[1], toolchain[1])
		}
	}
	t.Logf("go%s, in go.mod and in %d setup-go steps", toolchain[1], len(versions))
}
