package terraform

import (
	"math"
	"slices"
	"strings"
	"testing"
)

// TestStringValue: a string token decodes to its value with every escape
// resolved, and is refused, with the place named, for invalid UTF-8 and a
// lone surrogate escape, which encoding/json would repair to U+FFFD and
// the cloud parsers refuse; what is not a string token says what it is.
func TestStringValue(t *testing.T) {
	for raw, want := range map[string]string{
		`"plain"`:                   "plain",
		`"a\"b\\c\/d\b\f\n\r\t"`:    "a\"b\\c/d\b\f\n\r\t",
		`"caf\u00e9 \u00E9 \u0000"`: "café é \x00",
		`"\ud83d\ude00"`:            "😀",
		`"\uD83D\uDE00"`:            "😀",
		`  "padded"  `:              "padded",
		`"ü raw"`:                   "ü raw",
		`""`:                        "",
	} {
		got, err := stringValue([]byte(raw))
		if err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", raw, got, err, want)
		}
	}
	for raw, want := range map[string]string{
		"\"ab\xffc\"":        "holds invalid UTF-8 at byte 3 of the value as written",
		"\"\xc3\"":           "holds invalid UTF-8 at byte 1 of the value as written",
		"\"ab\xed\xa0\x80\"": "holds invalid UTF-8 at byte 3 of the value as written",
		`"\ud800"`:           `holds a lone UTF-16 surrogate escape, \ud800, in the value as written`,
		`"\udc00\ud800"`:     `holds a lone UTF-16 surrogate escape, \udc00, in the value as written`,
		`"\ud800\u0041"`:     `holds a lone UTF-16 surrogate escape, \ud800, in the value as written`,
		`"\ud800\n"`:         `holds a lone UTF-16 surrogate escape, \ud800, in the value as written`,
		`"\ud800x"`:          `holds a lone UTF-16 surrogate escape, \ud800, in the value as written`,
		`"\uDBFF\uDBFF"`:     `holds a lone UTF-16 surrogate escape, \uDBFF, in the value as written`,
		`5`:                  "is a number, not a string",
		`["x"]`:              "is a list, not a string",
		`null`:               "is null, not a string",
		``:                   "is absent",
	} {
		got, err := stringValue([]byte(raw))
		if err == nil || err.Error() != want {
			t.Errorf("%q: %q %v, want %q", raw, got, err, want)
		}
	}
}

// TestParseAddress: instance keys with dots, quotes and escapes inside
// them do not split an address, and an unclosed bracket runs to the end.
func TestParseAddress(t *testing.T) {
	cases := []struct {
		address string
		names   []string
		keys    []string
	}{
		{"aws_iam_role.deploy", []string{"aws_iam_role", "deploy"}, []string{"", ""}},
		{"aws_iam_role.counted[0]", []string{"aws_iam_role", "counted"}, []string{"", "[0]"}},
		{`module.ci[0].aws_iam_role.runner["a.b"]`, []string{"module", "ci", "aws_iam_role", "runner"}, []string{"", "[0]", "", `["a.b"]`}},
		{`aws_iam_role.x["a\"]b"]`, []string{"aws_iam_role", "x"}, []string{"", `["a\"]b"]`}},
		{`aws_iam_role.x["a\\"]`, []string{"aws_iam_role", "x"}, []string{"", `["a\\"]`}},
		{"aws_iam_role.x[", []string{"aws_iam_role", "x"}, []string{"", "["}},
		{"", []string{""}, []string{""}},
	}
	for _, c := range cases {
		steps := parseAddress(c.address)
		var names, keys []string
		for _, s := range steps {
			names, keys = append(names, s.name), append(keys, s.key)
		}
		if !slices.Equal(names, c.names) || !slices.Equal(keys, c.keys) {
			t.Errorf("%q: names %q keys %q, want %q %q", c.address, names, keys, c.names, c.keys)
		}
	}
	modules, local := configPath(`module.ci[0].module.inner["x.y"].data.aws_iam_policy_document.doc[2]`)
	if !slices.Equal(modules, []string{"ci", "inner"}) || local != "data.aws_iam_policy_document.doc" {
		t.Errorf("configPath: %v %q", modules, local)
	}
	if p := modulePrefix(`module.ci[0].module.inner["x.y"].aws_iam_role.a`); p != `module.ci[0].module.inner["x.y"].` {
		t.Errorf("modulePrefix: %q", p)
	}
	if p := modulePrefix("aws_iam_role.a"); p != "" {
		t.Errorf("modulePrefix of a root resource: %q", p)
	}
}

// TestResourceReference: a reference names a resource only when it
// reaches one, with the attribute and the instance key stripped.
func TestResourceReference(t *testing.T) {
	cases := map[string]string{
		"aws_iam_openid_connect_provider.gh.arn": "aws_iam_openid_connect_provider.gh",
		"aws_iam_openid_connect_provider.gh":     "aws_iam_openid_connect_provider.gh",
		"google_service_account.deploy[0].name":  "google_service_account.deploy",
		"data.aws_iam_policy_document.doc.json":  "data.aws_iam_policy_document.doc",
		`data.aws_iam_policy_document.doc["a"]`:  "data.aws_iam_policy_document.doc",
		"data.aws_iam_policy_document":           "",
		"local.sub":                              "",
		"var.org":                                "",
		"module.app.application_id":              "",
		"each.key":                               "",
		"count.index":                            "",
		"path.module":                            "",
		"terraform.workspace":                    "",
		"self.id":                                "",
		"gh":                                     "",
		"":                                       "",
		"azuread_application_registration.infra.client_id": "azuread_application_registration.infra",
	}
	for ref, want := range cases {
		got, ok := resourceReference(ref)
		if got != want || ok != (want != "") {
			t.Errorf("%q: %q %v, want %q", ref, got, ok, want)
		}
	}
}

// TestReferences: every references list beneath an attribute's
// expression is gathered, blocks included, duplicates and implied steps
// dropped, in document order.
func TestReferences(t *testing.T) {
	expressions := map[string]any{
		"oidc": []any{map[string]any{
			"allowed_audiences": map[string]any{"references": []any{"google_iam_workload_identity_pool.github.name", "google_iam_workload_identity_pool.github", 5}},
			"issuer_uri":        map[string]any{"constant_value": "x"},
		}},
		"assume_role_policy": map[string]any{"references": []any{"a.b.c", "a.b", "local.x", "a.b.c", "var.example[0]", "var.example", "a.b.d"}},
		"name":               map[string]any{"references": "not a list"},
	}
	if got := references(expressions, "oidc"); !slices.Equal(got, []string{"google_iam_workload_identity_pool.github.name"}) {
		t.Errorf("oidc: %v", got)
	}
	if got := references(expressions, "assume_role_policy"); !slices.Equal(got, []string{"a.b.c", "local.x", "var.example[0]", "a.b.d"}) {
		t.Errorf("assume_role_policy: %v", got)
	}
	if got := references(expressions, "name"); got != nil {
		t.Errorf("name: %v", got)
	}
	if got := references(nil, "x"); got != nil {
		t.Errorf("nil expressions: %v", got)
	}
}

// TestMarks: a mark is found beneath an attribute at any depth, a whole
// object marked true marks every attribute, and paths spell map keys and
// list elements as a customer would read them.
func TestMarks(t *testing.T) {
	m := marks{map[string]any{
		"attribute_mapping":  map[string]any{"google.subject": true, "attribute.repo": false},
		"oidc":               []any{map[string]any{"allowed_audiences": []any{false, true}}},
		"assume_role_policy": true,
		"name":               false,
		"tags":               map[string]any{},
		"list":               []any{},
	}}
	cases := map[string][]string{
		"attribute_mapping":  {`attribute_mapping["google.subject"]`},
		"oidc":               {"oidc[0].allowed_audiences[1]"},
		"assume_role_policy": {"assume_role_policy"},
		"name":               nil,
		"tags":               nil,
		"list":               nil,
		"absent":             nil,
	}
	for attribute, want := range cases {
		if got := m.paths(attribute); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", attribute, got, want)
		}
	}
	whole := marks{true}
	if got := whole.paths("anything"); !slices.Equal(got, []string{"anything"}) {
		t.Errorf("a whole object marked true: %v", got)
	}
	for _, v := range []any{false, nil, "text", []any{true}} {
		if got := (marks{v}).paths("x"); got != nil {
			t.Errorf("marks %v: %v", v, got)
		}
	}
	if !m.marked("oidc") || m.marked("name") {
		t.Errorf("marked: oidc %v name %v", m.marked("oidc"), m.marked("name"))
	}
}

// TestConsults: a leaf the row does not read is passed over, the block
// itself and its named leaves are not.
func TestConsults(t *testing.T) {
	oidc := Attribute{Name: "oidc", Leaves: []string{"allowed_audiences", "issuer_uri"}}
	for path, want := range map[string]bool{
		"oidc":                               true,
		"oidc[0]":                            true,
		"oidc[0].issuer_uri":                 true,
		"oidc[0].allowed_audiences":          true,
		"oidc[0].allowed_audiences[1]":       true,
		"oidc[0].jwks_json":                  false,
		"oidc[0].issuer_uri_extra":           false,
		`oidc[0].allowed_audiences_map["x"]`: false,
	} {
		if got := oidc.consults(path); got != want {
			t.Errorf("%s: %v, want %v", path, got, want)
		}
	}
	whole := Attribute{Name: "assume_role_policy"}
	if !whole.consults("assume_role_policy") || !whole.consults(`assume_role_policy["anything"]`) {
		t.Errorf("an attribute with no leaves is read whole")
	}
}

// TestCanonical: the reader's own statements render with sorted keys and
// no HTML escaping, and a value the encoder refuses is a programming
// error that panics rather than a statement that lies.
func TestCanonical(t *testing.T) {
	if got := string(canonical(map[string]any{"b": "<&>", "a": []string{"x"}})); got != `{"a":["x"],"b":"<&>"}` {
		t.Errorf("canonical: %s", got)
	}
	defer func() {
		if recover() == nil {
			t.Errorf("an unencodable value did not panic")
		}
	}()
	canonical(map[string]any{"x": math.NaN()})
}

// TestRawStateFile: the shapes that mark a raw state file, and the ones
// that resemble it without being one.
func TestRawStateFile(t *testing.T) {
	for raw, want := range map[string]bool{
		`{"lineage": "x"}`: true,
		`{"serial": 1}`:    true,
		`{"version": 4, "resources": [{"instances": []}]}`:   true,
		`{"version": 4, "resources": [{"name": "x"}]}`:       false,
		`{"version": 4, "resources": {}}`:                    false,
		`{"version": 4}`:                                     false,
		`{"version": "4", "resources": [{"instances": []}]}`: false,
		`{"format_version": "1.0", "values": {}}`:            false,
		`{"resources": [{"instances": []}]}`:                 false,
	} {
		m, err := decodeObject([]byte(raw))
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if got := m.rawStateFile(); got != want {
			t.Errorf("%s: %v, want %v", raw, got, want)
		}
	}
}

// TestDecodeObject: the sentence about a document that is not an object
// names what it is.
func TestDecodeObject(t *testing.T) {
	for raw, want := range map[string]string{
		`"x"`:   "the document is a string, not an object",
		`true`:  "the document is a boolean, not an object",
		`null`:  "the document is null, not an object",
		`5`:     "the document is a number, not an object",
		`[1]`:   "the document is a list, not an object",
		`   `:   "empty input",
		`{"a"`:  "not a JSON document",
		`[1,`:   "not a JSON document",
		`{} {}`: "not a JSON document",
	} {
		_, err := decodeObject([]byte(raw))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", raw, err, want)
		}
	}
	m, err := decodeObject([]byte(` {"a": 1} `))
	if err != nil || string(m["a"]) != "1" {
		t.Errorf("a padded object: %v %v", m, err)
	}
}

// TestConfigurationLookup: expressions are found through module calls by
// the instance's module names with keys stripped, and not found when a
// module or a resource is not described; a nil configuration describes
// nothing.
func TestConfigurationLookup(t *testing.T) {
	cfg, err := parseConfiguration(members{"root_module": []byte(`{
	  "resources": [{"address": "aws_iam_role.a", "expressions": {"assume_role_policy": {"references": ["local.x"]}}}, {"address": "aws_iam_role.a", "expressions": {"assume_role_policy": {"references": ["local.second"]}}}],
	  "module_calls": {
	    "ci": {"source": "./ci", "module": {"resources": [{"address": "aws_iam_role.runner", "expressions": {"assume_role_policy": {"references": ["var.org"]}}}],
	           "module_calls": {"inner": {"module": {"resources": [{"address": "aws_iam_role.deep"}]}}, "empty": {"source": "./empty"}}}}
	  }
	}`)})
	if err != nil {
		t.Fatalf("%v", err)
	}
	for address, want := range map[string][]string{
		"aws_iam_role.a":                                     {"local.x"},
		"aws_iam_role.a[3]":                                  {"local.x"},
		`module.ci[0].aws_iam_role.runner["build"]`:          {"var.org"},
		"module.ci.module.inner.aws_iam_role.deep":           nil,
		"module.ci.module.missing.aws_iam_role.deep":         nil,
		"module.empty.aws_iam_role.x":                        nil,
		"aws_iam_role.missing":                               nil,
		"module.ci[0].module.inner.aws_iam_role.deep[\"k\"]": nil,
	} {
		e, described := cfg.expressionsOf(address)
		if got := references(e, "assume_role_policy"); !slices.Equal(got, want) {
			t.Errorf("%s: references %v, want %v", address, got, want)
		}
		expectDescribed := !strings.Contains(address, "missing") && !strings.HasPrefix(address, "module.empty")
		if described != expectDescribed {
			t.Errorf("%s: described %v", address, described)
		}
	}
	if _, described := (*configModule)(nil).expressionsOf("aws_iam_role.a"); described {
		t.Errorf("a nil configuration describes something")
	}
	if cfg, err := parseConfiguration(members{}); cfg != nil || err != nil {
		t.Errorf("a configuration without root_module: %v %v", cfg, err)
	}
	for raw, want := range map[string]string{
		`{"resources": {}}`:                                     "configuration root_module.resources is not a list",
		`{"resources": [1]}`:                                    "configuration root_module.resources[0] is not a resource object",
		`{"resources": [{"expressions": []}]}`:                  "configuration root_module.resources[0] is not a resource object",
		`{"module_calls": []}`:                                  "configuration root_module.module_calls is not an object",
		`{"module_calls": {"x": 1}}`:                            "configuration root_module.module_calls.x is not a module call object",
		`{"module_calls": {"x": {"module": 1}}}`:                "configuration root_module.module_calls.x is not a module call object",
		`{"module_calls": {"x": {"module": {"resources": 1}}}}`: "configuration root_module.module_calls.x.module.resources is not a list",
	} {
		_, err := parseConfiguration(members{"root_module": []byte(raw)})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", raw, err, want)
		}
	}
}

// TestListed: the sentences spell one, two and three names as prose.
func TestListed(t *testing.T) {
	for _, c := range []struct {
		names []string
		want  string
	}{{nil, ""}, {[]string{"a"}, "a"}, {[]string{"a", "b"}, "a and b"}, {[]string{"a", "b", "c"}, "a, b and c"}} {
		if got := listed(c.names); got != c.want {
			t.Errorf("%v: %q", c.names, got)
		}
	}
	if plural([]string{"a"}, "is", "are") != "is" || plural([]string{"a", "b"}, "is", "are") != "are" {
		t.Errorf("plural")
	}
}
