package aws

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"testing"
)

// callerCase is one case of testdata/callers/cases.json at the top of the
// repository: a refusal's message, as AWS words it or forged, and the
// message as it must read without the person who made the call. The
// engine holds its own copy of the strip to the same table.
type callerCase struct {
	ID      string `json:"id"`
	Shape   string `json:"shape"`
	Message string `json:"message"`
	Want    string `json:"want"`
	Source  string `json:"source"`
}

const callerCases = "../../../testdata/callers/cases.json"

// callerShapes is how many cases of each shape the table holds. A loader
// that read fewer, or a shape gone from the table, would leave a form of
// the grammar unheld while every case left passed.
var callerShapes = map[string]int{
	"forged": 22, "assumed-role": 7, "iam-user": 6, "no-arn": 4, "iam-user-path": 4, "role-caller": 4,
	"assumed-role-sso": 3, "mfa": 3, "other-arn": 3, "federated-user": 2, "unanswered": 2, "u2f": 1, "root": 1,
}

// The table's size, and how many of its cases the strip must change.
const (
	callerCaseCount    = 62
	callerCasesChanged = 42
)

// callerTable reads the table, refusing a member it does not know,
// anything after the list, a case with an empty field, an id twice, and
// counts other than callerShapes'.
func callerTable(t *testing.T) []callerCase {
	t.Helper()
	raw, err := os.ReadFile(callerCases)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var cases []callerCase
	if err := decoder.Decode(&cases); err != nil {
		t.Fatalf("%s: %v", callerCases, err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		t.Fatalf("%s holds something after its list of cases (%v)", callerCases, err)
	}
	shapes, ids, changed := map[string]int{}, map[string]bool{}, 0
	for _, c := range cases {
		if c.ID == "" || c.Shape == "" || c.Message == "" || c.Want == "" || c.Source == "" {
			t.Fatalf("%s: a case with an empty field: %+v", callerCases, c)
		}
		if ids[c.ID] {
			t.Fatalf("%s: the id %s twice", callerCases, c.ID)
		}
		ids[c.ID] = true
		shapes[c.Shape]++
		if c.Want != c.Message {
			changed++
		}
	}
	if len(cases) != callerCaseCount || !maps.Equal(shapes, callerShapes) || changed != callerCasesChanged {
		t.Fatalf("%s holds %d cases of shapes %v, %d of them changed by the strip; it holds %d of shapes %v, %d changed",
			callerCases, len(cases), shapes, changed, callerCaseCount, callerShapes, callerCasesChanged)
	}
	return cases
}

// TestEveryCaseOfTheCallerTableReadsAsItsWant holds the collector's strip
// to the table, byte for byte, and each want to itself: a message already
// stripped is stripped to the same text.
func TestEveryCaseOfTheCallerTableReadsAsItsWant(t *testing.T) {
	cases := callerTable(t)
	matched, changed, fixed := 0, 0, 0
	for _, c := range cases {
		if got := withoutPeople(c.Message); got != c.Want {
			t.Errorf("%s (%s):\n got %+q\nwant %+q", c.ID, c.Shape, got, c.Want)
		} else {
			matched++
			if got != c.Message {
				changed++
			}
		}
		if again := withoutPeople(c.Want); again != c.Want {
			t.Errorf("%s: its want, stripped, reads %+q", c.ID, again)
		} else {
			fixed++
		}
	}
	t.Logf("%d of %d cases read as their want, %d of them changed; %d wants unchanged when stripped again", matched, len(cases), changed, fixed)
}
