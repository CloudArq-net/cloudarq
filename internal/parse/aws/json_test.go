package aws

import (
	"strings"
	"testing"
)

// names lists an object's member names in document order, duplicates included.
func names(v *value) []string {
	out := make([]string, len(v.members))
	for i, m := range v.members {
		out[i] = m.name
	}
	return out
}

func TestTreeKeepsDuplicateMembersAtEveryDepth(t *testing.T) {
	raw := []byte(`{"a":1,"a":2,"b":{"c":1,"c":2},"d":[{"e":1,"e":2}]}`)
	root, err := parseTree(raw)
	if err != nil {
		t.Fatalf("parseTree: %v", err)
	}
	if got := names(root); strings.Join(got, ",") != "a,a,b,d" {
		t.Errorf("root members = %v; the duplicate a must survive", got)
	}
	if got := names(root.members[2].value); strings.Join(got, ",") != "c,c" {
		t.Errorf("nested members = %v; the duplicate c must survive", got)
	}
	inArray := root.members[3].value.items[0]
	if got := names(inArray); strings.Join(got, ",") != "e,e" {
		t.Errorf("members inside an array = %v; the duplicate e must survive", got)
	}
	// Both values of a duplicate are kept, in order.
	if x, y := root.members[0].value.text, root.members[1].value.text; x != "1" || y != "2" {
		t.Errorf("duplicate values = %q, %q; want 1 then 2", x, y)
	}
}

// TestTreeRecordsExactByteRanges: a value's range starts at its first byte
// and ends after its last, whatever whitespace, separators and escapes
// surround it, so that Statement.Raw is the customer's own text and nothing
// else.
func TestTreeRecordsExactByteRanges(t *testing.T) {
	raw := []byte("{\n  \"Statement\" :  [ {\"Sid\":\"\\u0041 b\"} , 1.50 , true , null ]  ,\n  \"o\": { }\n}\n")
	root, err := parseTree(raw)
	if err != nil {
		t.Fatalf("parseTree: %v", err)
	}
	if got := string(raw[root.start:root.end]); got != strings.TrimSpace(string(raw)) {
		t.Errorf("root range = %q; want the object from { to }", got)
	}
	list := root.members[0].value
	// The expectations spell the \u escape with a doubled backslash so that
	// they hold the six source bytes, not the decoded letter.
	if got := string(raw[list.start:list.end]); got != "[ {\"Sid\":\"\\u0041 b\"} , 1.50 , true , null ]" {
		t.Errorf("array range = %q", got)
	}
	want := []string{"{\"Sid\":\"\\u0041 b\"}", "1.50", "true", "null"}
	for i, item := range list.items {
		if got := string(raw[item.start:item.end]); got != want[i] {
			t.Errorf("item %d range = %q, want %q", i, got, want[i])
		}
	}
	sid := list.items[0].members[0].value
	if sid.text != "A b" || string(raw[sid.start:sid.end]) != "\"\\u0041 b\"" {
		t.Errorf("escaped string: text %q, range %q; the text decodes and the range keeps the escape", sid.text, raw[sid.start:sid.end])
	}
	empty := root.members[1].value
	if got := string(raw[empty.start:empty.end]); got != "{ }" {
		t.Errorf("empty object range = %q", got)
	}
}

func TestTreeDecodesEveryKind(t *testing.T) {
	root, err := parseTree([]byte(`{"s":"a\"b","n":1e999,"z":-0,"f":1.0,"t":true,"x":false,"u":null,"l":[[]],"e":{}}`))
	if err != nil {
		t.Fatalf("parseTree: %v", err)
	}
	got := map[string]*value{}
	for _, m := range root.members {
		got[m.name] = m.value
	}
	if got["s"].kind != kindString || got["s"].text != `a"b` {
		t.Errorf("string = %+v", got["s"])
	}
	// Number text is kept verbatim: no float ever rounds what the anomaly quotes.
	for name, text := range map[string]string{"n": "1e999", "z": "-0", "f": "1.0"} {
		if got[name].kind != kindNumber || got[name].text != text {
			t.Errorf("number %s = %+v, want text %q", name, got[name], text)
		}
	}
	if got["t"].kind != kindBool || !got["t"].boolean || got["x"].kind != kindBool || got["x"].boolean {
		t.Errorf("booleans = %+v, %+v", got["t"], got["x"])
	}
	if got["u"].kind != kindNull {
		t.Errorf("null = %+v", got["u"])
	}
	if got["l"].kind != kindArray || len(got["l"].items) != 1 || got["l"].items[0].kind != kindArray || len(got["l"].items[0].items) != 0 {
		t.Errorf("nested array = %+v", got["l"])
	}
	if got["e"].kind != kindObject || len(got["e"].members) != 0 {
		t.Errorf("empty object = %+v", got["e"])
	}
}

// TestTreeRejectsWhatIsNotOneDocument pins the error boundary: anything
// that is not exactly one JSON value in valid UTF-8 is refused, with a
// reason a person can act on, and nothing is ever silently dropped from
// the end of the input.
func TestTreeRejectsWhatIsNotOneDocument(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"empty", "", "empty"},
		{"whitespace", " \n\t ", "empty"},
		{"second document", `{"a":1} {"a":2}`, "after the document"},
		{"trailing garbage", `{"a":1} xyz`, "after the document"},
		{"byte order mark", "\xEF\xBB\xBF{}", "invalid character"},
		{"invalid utf-8", "{\"k\":\"a\xffb\"}", "not valid UTF-8 at byte 7"},
		{"unterminated", `{"a":`, "unexpected EOF"},
		{"bad literal", `{"a":tru}`, "invalid character"},
		{"deep nesting", strings.Repeat("[", 20000) + strings.Repeat("]", 20000), "nested more than 1000 levels deep"},
	}
	for _, c := range cases {
		root, err := parseTree([]byte(c.raw))
		if err == nil {
			t.Errorf("%s: parsed %+v, want an error", c.name, root)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not mention %q", c.name, err, c.want)
		}
	}
	// A root that is not an object is a tree all the same; policy.go decides
	// what to say about it.
	for _, raw := range []string{`["x"]`, `"x"`, `42`, `null`} {
		if _, err := parseTree([]byte(raw)); err != nil {
			t.Errorf("%s: %v; any single JSON value is a tree", raw, err)
		}
	}
}

// TestTreeReportsPrematureEndInsideAValue: the end of the input inside an
// open object or array is an error wherever it lands, after a key, a
// value, a comma or an opening bracket. A reader that took the decoder's
// bare EOF as the end of the document would accept a truncated policy. The
// decoder words the end two ways, depending on whether More was asked
// first; after a key it is not, and the bare EOF is the reader's to name.
func TestTreeReportsPrematureEndInsideAValue(t *testing.T) {
	for _, raw := range []string{`{"a":1`, `[1`, `{"a":1,`, `[1,`, `{"a"`, `{`, `[`, `{"a":[1`, `{"a":{"b":1`, `{"a":"x`, `{"a":tr`} {
		root, err := parseTree([]byte(raw))
		if err == nil {
			t.Errorf("%s: parsed %+v, want an error", raw, root)
			continue
		}
		if msg := err.Error(); !strings.Contains(msg, "unexpected EOF") && !strings.Contains(msg, "unexpected end of JSON input") {
			t.Errorf("%s: error %q does not say the input ended early", raw, err)
		}
	}
	if _, err := parseTree([]byte(`{"a"`)); err == nil || !strings.Contains(err.Error(), "unexpected EOF") {
		t.Errorf("the end after a key is the reader's bare EOF to name; got %v", err)
	}
	if _, err := parseTree([]byte(`{"a":1 "b":2}`)); err == nil || !strings.Contains(err.Error(), "invalid character") {
		t.Errorf("a missing comma is a decode error, got %v", err)
	}
}

// TestTreeRefusesLoneSurrogateEscapes: a \uD800 with no low surrogate after
// it decodes to U+FFFD, silently, exactly as an invalid byte would, and an
// Exact built from that value would not be the customer's value. The
// escape is refused for the reason the raw byte is. A well-formed pair,
// an escaped backslash before a u, and a literal U+FFFD are all text.
func TestTreeRefusesLoneSurrogateEscapes(t *testing.T) {
	refused := []struct{ name, raw string }{
		{"high surrogate alone in a value", `{"k":"a\ud800b"}`},
		{"low surrogate alone in a value", `{"k":"a\udc00b"}`},
		{"high surrogate at the end", `{"k":"\uD800"}`},
		{"surrogate in a member name", `{"s\udc00ub":"x"}`},
		{"high surrogate followed by an ordinary escape", `{"k":"\ud800\u0041"}`},
		{"surrogate in an array", `["\uDBFF"]`},
	}
	for _, c := range refused {
		root, err := parseTree([]byte(c.raw))
		if err == nil {
			t.Errorf("%s: parsed %+v, want an error", c.name, root)
			continue
		}
		if !strings.Contains(err.Error(), "lone UTF-16 surrogate escape") {
			t.Errorf("%s: error %q does not name the surrogate", c.name, err)
		}
	}
	accepted := map[string]string{
		`{"k":"\ud83d\ude00"}`:     "\U0001F600",
		`{"k":"\\ud800"}`:          `\ud800`,
		`{"k":"\ufffd"}`:           "\uFFFD",
		"{\"k\":\"\xef\xbf\xbd\"}": "\uFFFD",
		`{"k":"\u0041\u00e9"}`:     "A\u00e9",
	}
	for raw, want := range accepted {
		root, err := parseTree([]byte(raw))
		if err != nil {
			t.Errorf("%s: %v; this is text", raw, err)
			continue
		}
		if got := root.members[0].value.text; got != want {
			t.Errorf("%s: decoded %q, want %q", raw, got, want)
		}
	}
	if _, err := ParseTrustPolicy([]byte(`{"Statement": [], "Id": "\ud800"}`)); err == nil || !strings.HasPrefix(err.Error(), "parse trust policy: ") {
		t.Errorf("the document is refused with its story: %v", err)
	}
}

// TestTreeBoundsNesting: the reader recurses once per level, and nothing
// the decoder promises bounds that. Go 1.24's Decoder.Token has no depth
// limit, so a document nested a few million levels deep overflowed the
// goroutine stack, a fatal error no recover can catch; later releases
// refuse at 10,000, so the answer depended on the toolchain. The reader's
// own bound is what makes the parser total, and is the same everywhere.
func TestTreeBoundsNesting(t *testing.T) {
	nested := func(depth int) string {
		return `{"Statement":` + strings.Repeat("[", depth) + strings.Repeat("]", depth) + "}"
	}
	if _, err := parseTree([]byte(nested(maxNesting - 1))); err != nil {
		t.Errorf("%d levels inside the document is within the bound: %v", maxNesting-1, err)
	}
	for _, depth := range []int{maxNesting, 100000, 2500000} {
		root, err := parseTree([]byte(nested(depth)))
		if err == nil {
			t.Fatalf("%d levels: parsed %v, want an error", depth, root.kind)
		}
		if want := "nested more than 1000 levels deep"; !strings.Contains(err.Error(), want) {
			t.Errorf("%d levels: error %q does not say %q", depth, err, want)
		}
	}
	// Objects count the same as arrays.
	deepObjects := `{"Statement":` + strings.Repeat(`{"Condition":`, maxNesting) + "{}" + strings.Repeat("}", maxNesting) + "}"
	if _, err := parseTree([]byte(deepObjects)); err == nil || !strings.Contains(err.Error(), "nested more than 1000 levels deep") {
		t.Errorf("nested objects: %v", err)
	}
	// The whole parser refuses it with its story rather than a Document.
	if _, err := ParseTrustPolicy([]byte(nested(2500000))); err == nil || !strings.HasPrefix(err.Error(), "parse trust policy: nested more than") {
		t.Errorf("ParseTrustPolicy: %v", err)
	}
}
