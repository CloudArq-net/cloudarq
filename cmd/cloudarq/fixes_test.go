package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const fixesCases = "../../testdata/fixes"

// fixesCase is one case of testdata/fixes, and the flags that declare its
// owners, one --owner for each line of its owners.txt.
func fixesCase(t *testing.T, name string) (path string, flags []string) {
	t.Helper()
	path = filepath.Join(fixesCases, name, "aws.json")
	owners, err := os.ReadFile(filepath.Join(fixesCases, name, "owners.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(owners), "\n"), "\n") {
		if line != "" {
			flags = append(flags, "--owner", line)
		}
	}
	return path, flags
}

// expectedFix is what a case's rationale says of the fix of the population
// read from one principal: its status, the check that refused it, and what
// a proven one removes.
type expectedFix struct {
	principal, status, check, removes string
}

// fixesExpected is what each case's rationale says, principal by principal.
// A principal not listed has no fix, or one in words.
var fixesExpected = map[string][]expectedFix{
	"01-single-leaf":                        {{"arn:aws:iam::111122223333:root", "proven", "", "statement"}},
	"02-one-of-several":                     {{"arn:aws:iam::111122223333:root", "proven", "", "principal"}, {"777788889999", "proven", "", "principal"}},
	"03-array-and-string":                   {{"arn:aws:iam::111122223333:root", "proven", "", "member"}, {"777788889999", "proven", "", "member"}},
	"04-escaped-characters":                 {{"arn:aws:iam::111122223333:root", "proven", "", "principal"}, {"arn:aws:iam::444455556666:role/deploy", "proven", "", "principal"}},
	"05-deny-names-the-outsider":            {{"arn:aws:iam::111122223333:root", "proven", "", "principal"}, {"444455556666", "proven", "", "principal"}},
	"06-notprincipal":                       {},
	"07-statement-holding-your-own-account": {{"arn:aws:iam::111122223333:root", "proven", "", "principal"}, {"arn:aws:iam::444455556666:root", "proven", "", "principal"}},
	"08-condition-scoped-leaf":              {{"arn:aws:iam::111122223333:root", "proven", "", "principal"}, {"444455556666", "proven", "", "principal"}},
	"09-unreadable-span":                    {{"111122223333", "proven", "", "principal"}, {"444455556666", "proven", "", "principal"}},
	"10-outsider-named-by-a-condition":      {{"*", "unproven", "leaf", ""}},
	"11-the-only-statement":                 {{"arn:aws:iam::111122223333:root", "proven", "", "policy"}},
	"12-a-kind-written-twice":               {{"arn:aws:iam::111122223333:root", "unproven", "placements", ""}, {"444455556666", "unproven", "placements", ""}},
	"13-account-named-twice":                {{"111122223333", "unproven", "owner", ""}, {"arn:aws:iam::111122223333:root", "unproven", "owner", ""}},
	"14-a-lone-statement-object":            {{"arn:aws:iam::111122223333:role/vendor-audit", "proven", "", "policy"}},
	"15-one-outsider-in-a-list-of-one":      {{"777788889999", "proven", "", "policy"}},
	"16-two-outsiders-in-a-lone-statement":  {{"arn:aws:iam::111122223333:root", "proven", "", "principal"}, {"777788889999", "proven", "", "principal"}},
	"17-your-own-beside-the-outsider":       {{"arn:aws:iam::111122223333:root", "proven", "", "principal"}, {"arn:aws:iam::444455556666:root", "proven", "", "principal"}},
}

// answerFixes is the fix of each population of an answer read from an AWS
// principal or from "*", by the principal's text, and every fix the
// answer's Deny grants carry.
type answerFixes struct {
	byPrincipal map[string][]expectedFix
	ofADeny     int
}

func fixesOf(t *testing.T, answer []byte) answerFixes {
	t.Helper()
	var a struct {
		Grants []struct {
			Effect      string `json:"effect"`
			Populations []struct {
				Place string `json:"place"`
				Way   *struct {
					Principal []struct{ Text, Member string } `json:"principal"`
					Fix       *struct {
						Status, Check string
						Edit          *struct{ Removes string } `json:"edit"`
					} `json:"fix"`
				} `json:"way"`
			} `json:"populations"`
		} `json:"grants"`
	}
	if err := json.Unmarshal(answer, &a); err != nil {
		t.Fatal(err)
	}
	out := answerFixes{byPrincipal: map[string][]expectedFix{}}
	for _, g := range a.Grants {
		for _, p := range g.Populations {
			if p.Way == nil || p.Way.Fix == nil || p.Way.Fix.Status == "words" || len(p.Way.Principal) == 0 {
				continue
			}
			if g.Effect == "Deny" {
				out.ofADeny++
			}
			f := expectedFix{principal: p.Way.Principal[0].Text, status: p.Way.Fix.Status, check: p.Way.Fix.Check}
			if p.Way.Fix.Edit != nil {
				f.removes = p.Way.Fix.Edit.Removes
			}
			out.byPrincipal[f.principal] = append(out.byPrincipal[f.principal], f)
		}
	}
	return out
}

// TestFixesGoldens runs every case of testdata/fixes end to end, with its
// owners declared through --owner: the JSON the command prints, and what
// --explain prints of who, how and the fix, beside the case's rationale.
// Each case's fixes are held to what its rationale says, principal by
// principal, so that a golden written again cannot carry a fix the
// rationale does not.
func TestFixesGoldens(t *testing.T) {
	entries, err := os.ReadDir(fixesCases)
	if err != nil {
		t.Fatal(err)
	}
	examined := 0
	for _, e := range entries {
		name := e.Name()
		path, owners := fixesCase(t, name)
		if _, err := os.Stat(filepath.Join(fixesCases, name, "rationale.md")); err != nil {
			t.Errorf("%s has no rationale: %v", name, err)
		}
		want, listed := fixesExpected[name]
		if !listed {
			t.Errorf("%s says nothing of its fixes in fixesExpected", name)
		}
		answer := ask(t, append(append([]string{"--json"}, owners...), path)...)
		explained := ask(t, append(append([]string{"--explain"}, owners...), path)...)
		if answer.code != 0 || explained.code != 0 {
			t.Fatalf("%s: exit %d and %d, %s", name, answer.code, explained.code, explained.stderr)
		}
		got := fixesOf(t, []byte(answer.stdout))
		if got.ofADeny != 0 {
			t.Errorf("%s: a Deny's grant has a fix", name)
		}
		count := 0
		for _, w := range want {
			if !slices.Contains(got.byPrincipal[w.principal], w) {
				t.Errorf("%s: the fixes of %q are %+v, want %+v among them", name, w.principal, got.byPrincipal[w.principal], w)
			}
		}
		for _, fixes := range got.byPrincipal {
			count += len(fixes)
		}
		if count != len(want) {
			t.Errorf("%s: %d fixes of a principal, the rationale says %d: %+v", name, count, len(want), got.byPrincipal)
		}
		for _, form := range []struct{ golden, text string }{{name + ".json", answer.stdout}, {name + ".explain.txt", explained.stderr}} {
			golden := filepath.Join("testdata", "fixes", form.golden)
			if *update {
				if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, []byte(form.text), 0o600); err != nil {
					t.Fatal(err)
				}
				continue
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if form.text != string(want) {
				t.Errorf("%s: the output is not the golden file\n--- got ---\n%s\n--- want ---\n%s", golden, form.text, want)
			}
		}
		examined++
	}
	if examined < 17 {
		t.Fatalf("%d fixes cases examined; the corpus did not load", examined)
	}
}
