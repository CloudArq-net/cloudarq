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
// in-process loop is TestDeterminismOfTheText, in internal/report; `make
// determinism` runs both, and every other TestDeterminism, in twenty fresh
// processes.
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
	// every rings case with the owners it declares, whose echo, rings and
	// owners must come out in one order in every process
	for _, name := range ringsCaseNames(t) {
		path, owners := ringsCase(t, name)
		args := append(append([]string{"--json"}, owners...), path)
		first := ask(t, args...)
		for i := 0; i < 2; i++ {
			if again := ask(t, args...); again.stdout != first.stdout || again.code != first.code {
				t.Fatalf("%v: run %d differs", args, i+2)
			}
			runs++
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
