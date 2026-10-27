package report

import (
	"errors"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// answersDir holds documents whose whole answer is kept as a reader sees
// it, each case a directory: the policy, aws.json; the owners it declares,
// one a line as --owner takes them, in owners.txt when it declares any; the
// rationale that says why the answer is right; and the goldens. The goldens
// are the answer's JSON as --json prints it, the answer as the command
// prints it, and what --explain says after the answer of who each grant
// lets in.
const answersDir = "testdata/answers"

var update = flag.Bool("update", false, "write the golden files of testdata/answers from this run, then read the rationale beside each and say why the new answer is right")

// answerCase is one case of testdata/answers: its policy and its owners.
func answerCase(t *testing.T, name string) (doc, owners []byte) {
	t.Helper()
	doc, err := os.ReadFile(filepath.Join(answersDir, name, "aws.json"))
	if err != nil {
		t.Fatal(err)
	}
	owners, err = os.ReadFile(filepath.Join(answersDir, name, "owners.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	return doc, owners
}

// answerCases is every case under testdata/answers, by name.
func answerCases(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(answersDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	if len(names) < 7 {
		t.Fatalf("%d cases under %s; the goldens would hold too little", len(names), answersDir)
	}
	return names
}

// TestAnswerGoldens holds every case of testdata/answers to its goldens.
func TestAnswerGoldens(t *testing.T) {
	for _, name := range answerCases(t) {
		doc, owners := answerCase(t, name)
		a := AnswerFor(doc, owners)
		explained := ""
		if lines := a.ExplainWays(""); len(lines) > 0 {
			explained = strings.Join(lines, "\n") + "\n"
		}
		for _, golden := range []struct{ file, got string }{
			{"answer.json", string(a.JSON()) + "\n"},
			{"answer.txt", a.Text(Options{})},
			{"explain.txt", explained},
		} {
			path := filepath.Join(answersDir, name, golden.file)
			if *update {
				if err := os.WriteFile(path, []byte(golden.got), 0o600); err != nil {
					t.Fatal(err)
				}
				continue
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if golden.got != string(want) {
				t.Errorf("%s: the answer is not the golden file\n--- got ---\n%s\n--- want ---\n%s", path, golden.got, want)
			}
		}
		// A golden with no rationale is folklore: the first time it
		// disagrees with reality, the file is what gets believed.
		if _, err := os.Stat(filepath.Join(answersDir, name, "rationale.md")); err != nil {
			t.Errorf("%s has no rationale beside it: %v", name, err)
		}
	}
	if *update {
		t.Log("golden files written; read each rationale and say why the new answer is right")
	}
}
