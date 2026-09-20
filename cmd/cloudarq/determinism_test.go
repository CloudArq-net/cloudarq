package main

import (
	"path/filepath"
	"testing"
)

// TestDeterminismOfTheCommand runs the command in fresh processes and
// compares bytes. Fresh processes are the half that matters: Go randomises
// map iteration per process, so an unsorted range in the rendering can be
// stable within one binary run and different in the next, which is how a
// bug of this class survives an in-process loop. The rendering's own
// in-process loop is TestDeterminismOfTheText, in internal/report, which
// `make determinism` runs in twenty fresh processes; this target is not in
// that gate, which reaches ./internal/... only.
func TestDeterminismOfTheCommand(t *testing.T) {
	runs := 0
	for path := range corpus(t) {
		for _, args := range [][]string{{path}, {"--json", path}} {
			first := ask(t, args...)
			for i := 0; i < 2; i++ {
				again := ask(t, args...)
				if again.stdout != first.stdout || again.stderr != first.stderr || again.code != first.code {
					t.Fatalf("%v: run %d differs", args, i+2)
				}
				runs++
			}
		}
	}
	// one document with many grants, many notes and several terms, through
	// the twenty fresh processes the determinism gate asks for
	many := filepath.Join(testdata, "policies", "11-principal-shapes.json")
	first := ask(t, many)
	for i := 0; i < 20; i++ {
		if again := ask(t, many); again.stdout != first.stdout {
			t.Fatalf("%s: process %d rendered differently", many, i+1)
		}
		runs++
	}
	t.Logf("%d fresh processes agreed byte for byte", runs)
}
