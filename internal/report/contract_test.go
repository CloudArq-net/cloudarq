package report

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/ring"
)

// The answer's members are read by their names, and a consumer reading one
// member by its name must not meet the same name meaning something else a
// level down: a count of lines beside a list of rows, a list of grants
// beside a list of their numbers, an echo of the owners declared beside the
// owners a grant is pinned to. These tests hold every name the answer and
// the explanation write to one meaning, over every document the corpus
// holds, read with owners declared and refused and with tokens.

// sameNameAlready are the names that carried two kinds of value before the
// rings, which the version rule keeps as they are: a token's count of
// claims beside an outcome's list of them, a claim's constraint beside the
// rendered constraint that excludes a token, and a grant's witness token
// beside whether a token is an outcome's witness. They are the only names
// allowed two kinds, and only these two.
var sameNameAlready = map[string][]string{
	"claims":     {"array of object", "number"},
	"constraint": {"object", "string"},
	"witness":    {"bool", "string"},
}

// contractSamples is every answer and explanation the contract tests read,
// as JSON: each case of testdata/rings with its own declaration, then with
// lines the engine refuses added to it, and explained for a token; every
// document of the grants and policy corpora; a document and a token that
// cannot be read; and a declaration past its bound.
func contractSamples(t *testing.T) [][]byte {
	t.Helper()
	token := []byte(`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:ref:refs/heads/main","repository_owner_id":"123456"}`)
	var out [][]byte
	add := func(doc, owners []byte) {
		out = append(out, AdmitsFor(doc, owners), ExplainFor(doc, token, owners))
	}
	for _, name := range ringsCases(t) {
		doc, owners := ringsCase(t, name)
		add(doc, owners)
		add(doc, append(append([]byte{}, owners...), "gitlab:x\nnope\ngithub:acme/infra\n"...))
	}
	var paths []string
	for _, pattern := range []string{"../../testdata/grants/*/aws.json", "../../testdata/policies/*.json", "testdata/escapes.json"} {
		found, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, found...)
	}
	for _, p := range paths {
		doc, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		add(doc, nil)
	}
	doc, _ := ringsCase(t, "01-branch-pin-and-owner-prefix")
	out = append(out,
		Admits([]byte("not a document")),
		Explain(doc, []byte("not a token")),
		AdmitsFor(doc, []byte(strings.Repeat("github:o\n", ring.MaxDeclarationLines+1))),
	)
	if len(out) < 200 {
		t.Fatalf("%d answers and explanations; the contract would be held over too few", len(out))
	}
	return out
}

// metAt is where one name was met: the path to it and the kind of value
// it held there.
type metAt struct{ path, kind string }

// members walks a decoded JSON value and records every object member it
// holds, by name, with the kind of value each held: an object, a string, a
// number, a bool, or an array by the kind of its elements. A null, or an
// array holding nothing but empty arrays, says nothing of the kind, and is
// not recorded.
func members(v any, path string, into map[string][]metAt) {
	switch v := v.(type) {
	case map[string]any:
		for name, value := range v {
			at := path + "." + name
			if kind := kindOf(value); kind != "" {
				into[name] = append(into[name], metAt{at, kind})
			}
			members(value, at, into)
		}
	case []any:
		for _, e := range v {
			members(e, path+"[]", into)
		}
	}
}

func kindOf(v any) string {
	switch v := v.(type) {
	case map[string]any:
		return "object"
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "bool"
	case []any:
		for _, e := range v {
			if kind := kindOf(e); kind != "" {
				return "array of " + kind
			}
		}
	}
	return ""
}

// qualified walks a decoded JSON value and reports every member named
// <something>State whose object holds no member named <something>: a
// member that qualifies another is named for the member it qualifies, as
// the state beside a place is its state.
func qualified(v any, path string, report func(path string)) {
	switch v := v.(type) {
	case map[string]any:
		for name, value := range v {
			if of, ok := strings.CutSuffix(name, "State"); ok {
				if _, beside := v[of]; !beside {
					report(path + "." + name)
				}
			}
			qualified(value, path+"."+name, report)
		}
	case []any:
		for _, e := range v {
			qualified(e, path+"[]", report)
		}
	}
}

// TestEveryMemberNameMeansOneThing: across every answer and explanation,
// each member name holds one kind of value wherever it is written, except
// the two names that already held two before the rings; and a member named
// for a state sits beside the member whose state it is.
func TestEveryMemberNameMeansOneThing(t *testing.T) {
	seen := map[string][]metAt{}
	unqualified := map[string]bool{}
	all := contractSamples(t)
	samples := len(all)
	for _, sample := range all {
		var v any
		if err := json.Unmarshal(sample, &v); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, sample)
		}
		members(v, "", seen)
		qualified(v, "", func(path string) { unqualified[path] = true })
	}
	for _, path := range slices.Sorted(maps.Keys(unqualified)) {
		t.Errorf("%s names a state and sits beside no member it is the state of", path)
	}
	for name, met := range seen {
		byKind := map[string][]string{}
		for _, m := range met {
			if !slices.Contains(byKind[m.kind], m.path) {
				byKind[m.kind] = append(byKind[m.kind], m.path)
			}
		}
		kinds := make([]string, 0, len(byKind))
		for k := range byKind {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		if allowed, ok := sameNameAlready[name]; ok {
			if !slices.Equal(kinds, allowed) {
				t.Errorf("%q holds %v; before the rings it held %v, and the version rule keeps it so", name, kinds, allowed)
			}
			continue
		}
		if len(kinds) > 1 {
			var where []string
			for _, k := range kinds {
				where = append(where, k+" at "+strings.Join(byKind[k], ", "))
			}
			t.Errorf("%q means %d things: %s", name, len(kinds), strings.Join(where, "; "))
		}
	}
	// every name the answer's types declare was met, so that no member
	// passed by being absent from every sample
	declared := map[string]bool{}
	for _, v := range []any{Answer{}, Explanation{}} {
		tagNames(reflect.TypeOf(v), declared, map[reflect.Type]bool{})
	}
	for name := range declared {
		if len(seen[name]) == 0 {
			t.Errorf("no sample writes %q; its meaning went unexamined", name)
		}
	}
	if !t.Failed() {
		t.Logf("%d member names declared, each met and each meaning one thing across %d answers and explanations", len(declared), samples)
	}
}

// tagNames collects the JSON names of every exported field of t and of the
// types it holds.
func tagNames(t reflect.Type, into map[string]bool, done map[reflect.Type]bool) {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || done[t] {
		return
	}
	done[t] = true
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name != "" && name != "-" {
			into[name] = true
		}
		tagNames(f.Type, into, done)
	}
}

// enumerated is every member whose values are a closed set, by the type
// and the JSON name the schema writes it under, with the set the engine
// draws its values from. A consumer reads a value it does not know as
// Unknown, which it can only do with the set it knows written down, so
// each is written beside its field after "Values:", and held here to the
// tables in internal/ring and the constants in this package.
func enumerated() map[string][]string {
	places := names(func(i int) string { return ring.Place(i).String() }, "place")
	states := names(func(i int) string { return ring.State(i).String() }, "state")
	outcomes := names(func(i int) string { return ring.Outcome(i).String() }, "outcome")
	// a placed grant's placement is its places; the other outcomes are
	// their own placement, and "placed" itself is never written
	placement := append(slices.Clone(places), slices.DeleteFunc(outcomes, func(o string) bool { return o == ring.Placed.String() })...)
	// the zero scope names no tenant and pins nothing, and the zero reason
	// is a line that declared an owner: neither is written by an owner or
	// by a refused line
	scopes := slices.DeleteFunc(names(func(i int) string { return ring.Scope(i).String() }, "scope"), func(s string) bool { return s == ring.ScopeNone.String() })
	reasons := slices.DeleteFunc(names(func(i int) string { return ring.Reason(i).String() }, "reason"), func(r string) bool { return r == ring.NoReason.String() })
	return map[string][]string{
		"Row.place":              places,
		"Row.state":              states,
		"Grant.placement":        placement,
		"Grant.placementState":   states,
		"Outcome.placement":      placement,
		"Outcome.placementState": states,
		"Population.place":       places,
		"Population.state":       states,
		"Population.basis":       names(func(i int) string { return ring.Basis(i).String() }, "basis"),
		"Owner.scope":            scopes,
		"Owner.kind":             names(func(i int) string { return ring.Kind(i).String() }, "kind"),
		"RefusedLine.reason":     reasons,
		"Bound.bound":            {rcpBound, scpBound, providersBound, settingsBound},
		"Explanation.result":     {refusedResult, admittedResult, notProvenResult, notAdmittedResult, notKnownResult},
	}
}

// names reads a ring name table through the values' String: every value
// from zero until the first the table does not hold, which the package
// renders as the kind and its number.
func names(of func(int) string, kind string) []string {
	var out []string
	for i := 0; ; i++ {
		s := of(i)
		if s == kind+"("+strconv.Itoa(i)+")" {
			return out
		}
		out = append(out, s)
	}
}

// writtenValues reads, from the schema's own source, the values written
// beside each field after "Values:", by type and JSON name.
func writtenValues(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	fset := gotoken.NewFileSet()
	for _, file := range []string{"answer.go", "explain.go"} {
		f, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			spec, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			fields, ok := spec.Type.(*ast.StructType)
			if !ok {
				return false
			}
			for _, field := range fields.Fields.List {
				_, list, found := strings.Cut(strings.Join(strings.Fields(field.Doc.Text()), " "), "Values: ")
				if !found || field.Tag == nil {
					continue
				}
				list, _, _ = strings.Cut(list, ".")
				tag, _ := strconv.Unquote(field.Tag.Value)
				name, _, _ := strings.Cut(reflect.StructTag(tag).Get("json"), ",")
				out[spec.Name.Name+"."+name] = strings.Split(list, ", ")
			}
			return false
		})
	}
	return out
}

// valueAt maps where the corpus writes an enumerated value to the field
// that declares it.
var valueAt = map[string]string{
	".rings[].place":                         "Row.place",
	".beside[].place":                        "Row.place",
	".rings[].state":                         "Row.state",
	".beside[].state":                        "Row.state",
	".grants[].placement[]":                  "Grant.placement",
	".grants[].placementState":               "Grant.placementState",
	".grants[].populations[].place":          "Population.place",
	".grants[].populations[].state":          "Population.state",
	".grants[].populations[].basis":          "Population.basis",
	".grants[].populations[].owners[].scope": "Owner.scope",
	".grants[].populations[].owners[].kind":  "Owner.kind",
	".declarations.refusedLines[].reason":    "RefusedLine.reason",
	".bounds.items[].bound":                  "Bound.bound",
	".result":                                "Explanation.result",
}

// valuesAt walks a decoded JSON value and calls at with every string it
// holds and the path to it.
func valuesAt(v any, path string, at func(path, value string)) {
	switch v := v.(type) {
	case map[string]any:
		for name, value := range v {
			valuesAt(value, path+"."+name, at)
		}
	case []any:
		for _, e := range v {
			valuesAt(e, path+"[]", at)
		}
	case string:
		at(path, v)
	}
}

// TestTheValueSetsAreWritten: each enumerated member lists its values
// beside its field, the list is the set the engine draws them from, and
// every value the corpus writes there is on it.
func TestTheValueSetsAreWritten(t *testing.T) {
	want, written := enumerated(), writtenValues(t)
	for field, values := range want {
		got, ok := written[field]
		switch {
		case !ok:
			t.Errorf("%s writes no values beside it; want %q", field, values)
		case !slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(values))):
			t.Errorf("%s writes the values %q; the engine draws them from %q", field, got, values)
		}
	}
	for field := range written {
		if _, ok := want[field]; !ok {
			t.Errorf("%s writes values beside it that no test holds to the engine's", field)
		}
	}
	met, unlisted := map[string]int{}, map[string]bool{}
	for _, sample := range contractSamples(t) {
		var v any
		if err := json.Unmarshal(sample, &v); err != nil {
			t.Fatal(err)
		}
		// an explanation's grants are outcomes, at the same paths
		_, explanation := v.(map[string]any)["token"]
		valuesAt(v, "", func(path, value string) {
			field, ok := valueAt[path]
			if !ok {
				return
			}
			if rest, grant := strings.CutPrefix(field, "Grant."); grant && explanation {
				field = "Outcome." + rest
			}
			met[field]++
			if !slices.Contains(written[field], value) {
				unlisted[path+" holds "+strconv.Quote(value)+", which the values written beside "+field+" do not list"] = true
			}
		})
	}
	for _, e := range slices.Sorted(maps.Keys(unlisted)) {
		t.Error(e)
	}
	for field := range want {
		if met[field] == 0 {
			t.Errorf("no sample writes %s; its values went unexamined", field)
		}
	}
}
