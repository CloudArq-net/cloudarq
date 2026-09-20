package terraform

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// members is one JSON object decoded one level. The readers tell a plan
// from a state from a raw state file by which members the top level has
// before reading any of them, and every level below is decoded only as
// far as the format documents it, so that an unrecognised member is
// carried past rather than refused, as the format asks.
type members map[string]json.RawMessage

// moduleDepthLimit bounds the module trees the readers descend, in the
// state's child_modules and the configuration's module_calls. Both are
// documented as recursive with no bound, and each is walked by recursion
// here; a tree deeper than any configuration has is refused rather than
// followed.
const moduleDepthLimit = 64

// decodeObject decodes a document into its top-level members, refusing
// what is not one JSON object.
func decodeObject(raw []byte) (members, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("empty input")
	}
	if trimmed[0] != '{' {
		if !json.Valid(trimmed) {
			return nil, fmt.Errorf("not a JSON document: %s", jsonError(trimmed))
		}
		return nil, fmt.Errorf("the document is %s, not an object", jsonKind(trimmed))
	}
	var m members
	if err := json.Unmarshal(trimmed, &m); err != nil {
		return nil, fmt.Errorf("not a JSON document: %s", jsonError(trimmed))
	}
	return m, nil
}

// jsonError is the decoder's own sentence about a document it refuses.
func jsonError(raw []byte) string {
	var v any
	return json.Unmarshal(raw, &v).Error()
}

// jsonKind names the JSON type of a value by its first byte, for the
// sentence about a document that is not an object.
func jsonKind(raw []byte) string {
	switch raw[0] {
	case '{':
		return "an object"
	case '[':
		return "a list"
	case '"':
		return "a string"
	case 't', 'f':
		return "a boolean"
	case 'n':
		return "null"
	}
	return "a number"
}

// isObject reports whether a JSON value is an object, by its first byte.
func isObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '{'
}

// isNull reports whether a raw value is null or missing altogether.
func isNull(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null"))
}

// isString reports whether a JSON value is a string token, by its first
// byte.
func isString(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '"'
}

// stringValue is the value of a JSON string token as the document writes
// it: the escapes resolved and nothing repaired. encoding/json decodes a
// string by replacing invalid UTF-8 and a lone UTF-16 surrogate escape
// with U+FFFD, and the cloud parsers refuse both, so a value decoded that
// way would be a document the parser accepts where it refuses the
// customer's own. Both are refused here instead, with the place named.
// The token has passed the decoder that read the document, so its escapes
// are well formed and every control character is escaped.
func stringValue(raw json.RawMessage) (string, error) {
	token := bytes.TrimSpace(raw)
	if len(token) == 0 {
		return "", errors.New("is absent")
	}
	if !isString(token) {
		return "", errors.New("is " + jsonKind(token) + ", not a string")
	}
	for i := 0; i < len(token); {
		r, size := utf8.DecodeRune(token[i:])
		if r == utf8.RuneError && size == 1 {
			return "", fmt.Errorf("holds invalid UTF-8 at byte %d of the value as written", i)
		}
		i += size
	}
	body := token[1 : len(token)-1]
	out := make([]byte, 0, len(body))
	for i := 0; i < len(body); i++ {
		if body[i] != '\\' {
			out = append(out, body[i])
			continue
		}
		i++
		switch body[i] {
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r := hexRune(body[i+1 : i+5])
			i += 4
			if utf16.IsSurrogate(r) {
				paired := r < 0xDC00 && i+6 < len(body) && body[i+1] == '\\' && body[i+2] == 'u' && utf16.DecodeRune(r, hexRune(body[i+3:i+7])) != utf8.RuneError
				if !paired {
					return "", fmt.Errorf("holds a lone UTF-16 surrogate escape, %s, in the value as written", body[i-5:i+1])
				}
				r = utf16.DecodeRune(r, hexRune(body[i+3:i+7]))
				i += 6
			}
			out = utf8.AppendRune(out, r)
		default:
			// The quote, the backslash and the solidus escape themselves.
			out = append(out, body[i])
		}
	}
	return string(out), nil
}

// hexRune reads the four hex digits of a \u escape, which the decoder that
// read the document has already checked.
func hexRune(digits []byte) rune {
	var r rune
	for _, c := range digits {
		switch {
		case c >= '0' && c <= '9':
			r = r<<4 | rune(c-'0')
		case c >= 'a' && c <= 'f':
			r = r<<4 | rune(c-'a'+10)
		default:
			r = r<<4 | rune(c-'A'+10)
		}
	}
	return r
}

// list decodes a member as a list, nil when it is absent or null.
func (m members) list(name, where string) ([]json.RawMessage, error) {
	raw, ok := m[name]
	if !ok || isNull(raw) {
		return nil, nil
	}
	var out []json.RawMessage
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("%s is not a list", where)
	}
	return out, nil
}

// object decodes a member as an object, nil when it is absent or null.
func (m members) object(name, where string) (members, error) {
	raw, ok := m[name]
	if !ok || isNull(raw) {
		return nil, nil
	}
	var out members
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("%s is not an object", where)
	}
	return out, nil
}

// text decodes a member as a string, false when it is absent, null or
// not a string: the members read this way label a document, and a label
// of another type is not a refusal.
func (m members) text(name string) (string, bool) {
	var s string
	if raw, ok := m[name]; ok && !isNull(raw) && json.Unmarshal(raw, &s) == nil {
		return s, true
	}
	return "", false
}

// flag decodes a member as a boolean, nil when it is absent or not one.
func (m members) flag(name string) *bool {
	var b bool
	if raw, ok := m[name]; ok && json.Unmarshal(raw, &b) == nil {
		return &b
	}
	return nil
}

// formatVersion reads the documented version key and refuses a major
// version this reader does not understand: "We will increment the major
// version, e.g. "2.0", for changes that are not backward-compatible.
// Reject any input which reports an unsupported major version."
func (m members) formatVersion() (string, error) {
	raw, ok := m["format_version"]
	if !ok {
		return "", errors.New("no format_version member; this is not terraform show -json output")
	}
	var version string
	if err := json.Unmarshal(raw, &version); err != nil {
		return "", errors.New("format_version is not a string; this is not terraform show -json output")
	}
	major, _, _ := strings.Cut(version, ".")
	n, err := strconv.Atoi(major)
	if err != nil {
		return "", fmt.Errorf("format_version %q does not begin with a major version number", version)
	}
	if n != 1 {
		return "", fmt.Errorf("format_version %q is major version %d; this reader understands major version 1, and HashiCorp says to reject any input which reports an unsupported major version", version, n)
	}
	return version, nil
}

// rawStateFile reports whether the document is a terraform.tfstate file
// rather than terraform show -json output: it carries a lineage or a
// serial, which only the state file has, or a numeric version beside a
// resources list whose entries hold instances. Such a file carries every
// sensitive value of every resource in clear and is never read.
func (m members) rawStateFile() bool {
	if _, ok := m["lineage"]; ok {
		return true
	}
	if _, ok := m["serial"]; ok {
		return true
	}
	var version float64
	if raw, ok := m["version"]; !ok || json.Unmarshal(raw, &version) != nil {
		return false
	}
	var resources []members
	if raw, ok := m["resources"]; !ok || json.Unmarshal(raw, &resources) != nil {
		return false
	}
	return slices.ContainsFunc(resources, func(r members) bool { _, ok := r["instances"]; return ok })
}

// planMarks are the top-level members only a plan has. A document with
// none of them and a values member is a state.
var planMarks = []string{"resource_changes", "planned_values", "configuration", "prior_state"}

func (m members) planMark() string {
	for _, mark := range planMarks {
		if _, ok := m[mark]; ok {
			return mark
		}
	}
	return ""
}

// step is one step of a resource address: a name and, when the step is
// an instance of a counted or for_each resource or module, its key as
// written between the brackets, quotes included.
type step struct {
	name string
	key  string
}

// parseAddress splits an absolute or module-local address into its steps.
// Dots split steps only outside brackets, and a bracketed key may hold a
// quoted string with dots or escaped quotes inside it, as
// module.child[0].aws_iam_role.runner["a.b"] does. The format calls
// addresses opaque and fit for string comparison; the reader parses them
// only to strip instance keys for the configuration lookup, where the
// same address is written without them.
func parseAddress(address string) []step {
	var steps []step
	var current step
	for i := 0; i < len(address); i++ {
		switch c := address[i]; {
		case c == '.':
			steps = append(steps, current)
			current = step{}
		case c == '[':
			end := closingBracket(address, i)
			current.key = address[i : end+1]
			i = end
		default:
			current.name += string(c)
		}
	}
	return append(steps, current)
}

// closingBracket finds the bracket that closes the one at open, skipping
// a quoted key and the escapes inside it. An unclosed bracket runs to the
// end of the address.
func closingBracket(address string, open int) int {
	quoted := false
	for i := open + 1; i < len(address); i++ {
		switch {
		case quoted && address[i] == '\\':
			i++
		case address[i] == '"':
			quoted = !quoted
		case !quoted && address[i] == ']':
			return i
		}
	}
	return len(address) - 1
}

// configPath is where the configuration describes a resource instance:
// the module names on the way down, and the resource's module-local
// address with no instance key.
func configPath(address string) (modules []string, local string) {
	steps := parseAddress(address)
	for len(steps) >= 2 && steps[0].name == "module" {
		modules = append(modules, steps[1].name)
		steps = steps[2:]
	}
	names := make([]string, len(steps))
	for i, s := range steps {
		names[i] = s.name
	}
	return modules, strings.Join(names, ".")
}

// modulePrefix is the module part of an absolute address, with the dot
// that joins it to the resource, or "" for the root module.
func modulePrefix(address string) string {
	steps := parseAddress(address)
	var prefix string
	for len(steps) >= 2 && steps[0].name == "module" {
		prefix += "module." + steps[1].name + steps[1].key + "."
		steps = steps[2:]
	}
	return prefix
}

// resourceReference is the resource a configuration reference names, as
// a module-local address with no attribute and no key, and false for a
// reference to a variable, a local, a module, or an instance's own count
// or each: "aws_iam_openid_connect_provider.gh.arn" names
// aws_iam_openid_connect_provider.gh, and "data.aws_iam_policy_document.doc.json"
// names data.aws_iam_policy_document.doc.
func resourceReference(reference string) (string, bool) {
	steps := parseAddress(reference)
	switch steps[0].name {
	case "var", "local", "module", "each", "count", "path", "terraform", "self", "":
		return "", false
	case "data":
		if len(steps) < 3 {
			return "", false
		}
		return "data." + steps[1].name + "." + steps[2].name, true
	}
	if len(steps) < 2 {
		return "", false
	}
	return steps[0].name + "." + steps[1].name, true
}

// configResource is one resource of the configuration representation.
// The expressions are decoded whole, so that the references beneath an
// attribute, blocks included, can be gathered by a walk.
type configResource struct {
	Address     string         `json:"address"`
	Expressions map[string]any `json:"expressions"`
}

// configCall is one module call: the body of the module it calls, when
// the configuration holds it.
type configCall struct {
	Module members `json:"module"`
}

// configModule is one module of the configuration: the expressions of
// each resource it declares, by module-local address, and the modules it
// calls.
type configModule struct {
	expressions map[string]map[string]any
	calls       map[string]*configModule
}

// parseConfiguration reads configuration.root_module and its module_calls
// recursively. Nothing but resources and calls is read; provider blocks,
// outputs and variables are carried past.
func parseConfiguration(top members) (*configModule, error) {
	root, err := top.object("root_module", "configuration root_module")
	if err != nil || root == nil {
		return nil, err
	}
	return parseConfigModule(root, "root_module", 0)
}

func parseConfigModule(m members, where string, depth int) (*configModule, error) {
	if depth > moduleDepthLimit {
		return nil, fmt.Errorf("configuration nested more than %d module levels deep at %s", moduleDepthLimit, where)
	}
	out := &configModule{expressions: map[string]map[string]any{}, calls: map[string]*configModule{}}
	resources, err := m.list("resources", "configuration "+where+".resources")
	if err != nil {
		return nil, err
	}
	for i, raw := range resources {
		var r configResource
		if !isObject(raw) || json.Unmarshal(raw, &r) != nil {
			return nil, fmt.Errorf("configuration %s.resources[%d] is not a resource object", where, i)
		}
		if _, seen := out.expressions[r.Address]; !seen {
			out.expressions[r.Address] = r.Expressions
		}
	}
	calls, err := m.object("module_calls", "configuration "+where+".module_calls")
	if err != nil {
		return nil, err
	}
	for _, name := range sortedKeys(calls) {
		var call configCall
		if !isObject(calls[name]) || json.Unmarshal(calls[name], &call) != nil {
			return nil, fmt.Errorf("configuration %s.module_calls.%s is not a module call object", where, name)
		}
		if call.Module == nil {
			continue
		}
		child, err := parseConfigModule(call.Module, where+".module_calls."+name+".module", depth+1)
		if err != nil {
			return nil, err
		}
		out.calls[name] = child
	}
	return out, nil
}

// sortedKeys lists a map's keys in order, so that nothing here iterates
// a map into output.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// expressionsOf finds the block expressions of the resource an instance
// address names, false when the configuration does not describe it.
func (c *configModule) expressionsOf(address string) (map[string]any, bool) {
	if c == nil {
		return nil, false
	}
	modules, local := configPath(address)
	m := c
	for _, name := range modules {
		child, ok := m.calls[name]
		if !ok {
			return nil, false
		}
		m = child
	}
	e, ok := m.expressions[local]
	return e, ok
}

// references lists what the expression of an attribute references, as
// the configuration states it: every references list beneath the
// attribute's expression, blocks included, in document order, each
// reference once, and without the entries the format says are implied
// by a later step of the same traversal, such as
// aws_iam_openid_connect_provider.gh beside aws_iam_openid_connect_provider.gh.arn.
func references(expressions map[string]any, attribute string) []string {
	var found []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if refs, ok := x["references"].([]any); ok {
				for _, r := range refs {
					if s, ok := r.(string); ok {
						found = append(found, s)
					}
				}
			}
			for _, k := range sortedKeys(x) {
				if k != "references" {
					walk(x[k])
				}
			}
		case []any:
			for _, item := range x {
				walk(item)
			}
		}
	}
	walk(expressions[attribute])
	return withoutImplied(found)
}

// withoutImplied drops exact duplicates and every reference that a
// longer reference in the list begins with, keeping first-seen order.
func withoutImplied(refs []string) []string {
	var out []string
	for i, r := range refs {
		if slices.Contains(refs[:i], r) {
			continue
		}
		implied := slices.ContainsFunc(refs, func(other string) bool {
			return other != r && (strings.HasPrefix(other, r+".") || strings.HasPrefix(other, r+"["))
		})
		if !implied {
			out = append(out, r)
		}
	}
	return out
}

// marks is an after_unknown, after_sensitive or sensitive_values value
// decoded whole: a structure like the value's with true at every marked
// leaf and the known or plain leaves omitted or false, or a bare boolean
// for the whole object.
type marks struct{ v any }

// paths lists every path beneath an attribute at which the marks hold
// true, in a stable order: the attribute itself when it is marked whole,
// else oidc[0].allowed_audiences[1] or attribute_mapping["google.subject"]
// for a leaf inside it. A container marked true marks everything beneath
// it, and a list element or map entry that is null or missing beside a
// true mark is exactly what the format documents an unknown leaf as, so
// a mark is looked for beneath the attribute, never only at it.
func (m marks) paths(attribute string) []string {
	if m.v == true {
		return []string{attribute}
	}
	obj, ok := m.v.(map[string]any)
	if !ok {
		return nil
	}
	var out []string
	var walk func(v any, path string)
	walk = func(v any, path string) {
		switch x := v.(type) {
		case bool:
			if x {
				out = append(out, path)
			}
		case map[string]any:
			for _, k := range sortedKeys(x) {
				walk(x[k], path+memberPath(k))
			}
		case []any:
			for i, item := range x {
				walk(item, path+"["+strconv.Itoa(i)+"]")
			}
		}
	}
	walk(obj[attribute], attribute)
	return out
}

// marked reports whether any leaf beneath the attribute is marked.
func (m marks) marked(attribute string) bool { return len(m.paths(attribute)) > 0 }

// memberPath spells one object member on a path: dotted when the key is
// an attribute or block name, bracketed when it is a map key that would
// not read as one.
func memberPath(key string) string {
	for _, c := range key {
		if !(c == '_' || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return "[" + strconv.Quote(key) + "]"
		}
	}
	return "." + key
}

// canonical renders a value as canonical JSON: sorted keys, no HTML
// escaping, no trailing newline. It renders only what the reader itself
// states, built from strings, booleans, lists, maps and raw values cut
// from a document the decoder accepted; a value the encoder refuses is a
// programming error, not a document.
func canonical(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}
