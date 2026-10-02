package arch

import (
	"encoding/json"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// TestTheEngineModuleReachesNoCloudSDK holds the line the collector was
// built along: the engine reads a bundle offline and never calls a cloud,
// so no package of this module - the CLI and the WebAssembly build
// included, not only the pure layers - may reach a cloud SDK. The SDK lives
// in the collector's own module, internal/collect, which ./... does not
// enter.
func TestTheEngineModuleReachesNoCloudSDK(t *testing.T) {
	out, err := exec.Command("go", "list", "-e", "-deps", "-test", "-json", "../../...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	examined := 0
	decoder := json.NewDecoder(strings.NewReader(string(out)))
	for decoder.More() {
		var p struct{ ImportPath string }
		if err := decoder.Decode(&p); err != nil {
			t.Fatalf("decode: %v", err)
		}
		examined++
		if slices.ContainsFunc(forbiddenPrefixes, func(pre string) bool { return strings.HasPrefix(p.ImportPath, pre) }) {
			t.Errorf("%s is in the engine's build: a cloud SDK belongs to the collector's module alone", p.ImportPath)
		}
		if strings.HasPrefix(p.ImportPath, modulePrefix+"internal/collect") {
			t.Errorf("%s is in the engine's build: the collector is its own module", p.ImportPath)
		}
	}
	if examined == 0 {
		t.Fatal("go list named no package, so this test proved nothing")
	}
	t.Logf("examined %d packages of the engine's build and its tests", examined)
}
