package terraform

import (
	"bytes"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/trust"
	"pgregory.net/rapid"
)

// The generated corpus. A spec is a plan or a state built from resource
// specs, each of which draws its family, its place in the module tree,
// its instance key, its action, the state of the attribute the reader
// consults: known, marked unknown at the top, marked unknown one level
// down, absent or null, and, apart from that, whether the attribute is
// marked sensitive. The properties below read the spec by their own hand
// and hold the reader to it.

type family string

const (
	awsRole        family = "aws_iam_role"
	entraCred      family = "azuread_application_federated_identity_credential"
	armCred        family = "azurerm_federated_identity_credential"
	googleProvider family = "google_iam_workload_identity_pool_provider"
	googleMember   family = "google_service_account_iam_member"
	googleBinding  family = "google_service_account_iam_binding"
	googlePolicy   family = "google_service_account_iam_policy"
	unmapped       family = "awscc_iam_role"
	unrelated      family = "aws_iam_openid_connect_provider"
)

var specFamilies = []family{awsRole, entraCred, armCred, googleProvider, googleMember, googleBinding, googlePolicy, unmapped, unrelated}

// mapped reports whether the table reads the family.
func (f family) mapped() bool { return f != unmapped && f != unrelated }

// valueState is the state of one admission attribute in the document.
type valueState string

const (
	known       valueState = "known"
	unknownTop  valueState = "unknown"        // marked at the attribute
	unknownDeep valueState = "unknown-nested" // marked one level down
	absent      valueState = "absent"         // the key is missing and unmarked
	null        valueState = "null"
)

var valueStates = []valueState{known, known, known, unknownTop, unknownDeep, absent, null}

// actions are the change actions a plan spec draws, plus two of the
// reader's own: "create-forget" is the ["create", "forget"] replace, and
// "unlisted" a resource the plan lists no change for and its prior state
// holds, as a refresh-only or targeted plan leaves one.
var actions = []string{"create", "create", "update", "no-op", "delete", "replace", "forget", "create-forget", "unlisted"}

// inChanges reports whether an action puts the resource in resource_changes.
func inChanges(action string) bool { return action != "unlisted" }

// existed reports whether an action means the resource was in the state
// the plan is applied to, and so in prior_state.
func existed(action string) bool { return action != "create" }

// objects lists the sides the reader reads of a change with the action:
// after, before, or both, or the prior state.
func objects(action string) []string {
	switch action {
	case "delete", "forget":
		return []string{"before"}
	case "create-forget":
		return []string{"after", "before"}
	case "unlisted":
		return []string{"prior_state"}
	}
	return []string{"after"}
}

// targetState is the state of the attribute that names the target.
type targetState string

const (
	targetKnown      targetState = "known"
	targetOne        targetState = "unknown-one"  // unknown, referencing a resource with one instance
	targetMany       targetState = "unknown-many" // unknown, referencing a resource with two instances
	targetUnresolved targetState = "unknown-none" // unknown, referencing nothing in the plan
)

var targetStates = []targetState{targetKnown, targetKnown, targetOne, targetMany, targetUnresolved}

type resourceSpec struct {
	family  family
	module  []string // module names, root when empty
	keys    []string // instance key per module step, "" for none
	key     string   // the resource's own instance key, "" for none
	name    string
	action  string
	value   valueState
	marked  bool // the admission attribute is marked sensitive
	target  targetState
	subject string
	poolID  string // the pool a google provider serves, or a member names
}

func (r resourceSpec) typeName() string { return string(r.family) }

// address is the absolute instance address.
func (r resourceSpec) address() string {
	var b strings.Builder
	for i, m := range r.module {
		b.WriteString("module." + m + r.keys[i] + ".")
	}
	b.WriteString(r.typeName() + "." + r.name + r.key)
	return b.String()
}

func (r resourceSpec) moduleAddress() string {
	var b strings.Builder
	for i, m := range r.module {
		if i > 0 {
			b.WriteString(".")
		}
		b.WriteString("module." + m + r.keys[i])
	}
	return b.String()
}

// admission is the attribute the spec's value state applies to: the one
// the property expects to see named.
func (r resourceSpec) admission() string {
	switch r.family {
	case awsRole:
		return "assume_role_policy"
	case entraCred, armCred:
		return "subject"
	case googleProvider:
		return "attribute_condition"
	case googleMember:
		return "member"
	case googleBinding:
		return "members"
	case googlePolicy:
		return "policy_data"
	}
	return "assume_role_policy_document"
}

// nested is the path the deep mark lands on, for the families that have
// a container attribute; the others nest nothing and the deep state reads
// as the top one.
func (r resourceSpec) nested() string {
	switch r.family {
	case entraCred:
		return "audiences[0]"
	case armCred:
		return "audience[0]"
	case googleProvider:
		return "oidc[0].allowed_audiences[1]"
	case googleBinding:
		return "members[1]"
	}
	return ""
}

func genKey() *rapid.Generator[string] {
	return rapid.OneOf(rapid.Just(""), rapid.Just("[0]"), rapid.Just("[1]"), rapid.Just(`["a"]`), rapid.Just(`["b.c"]`))
}

func genSubject() *rapid.Generator[string] {
	return rapid.StringOfN(rapid.RuneFrom([]rune("ab/:*")), 1, 6, -1)
}

func genResource(names []string) *rapid.Generator[resourceSpec] {
	return rapid.Custom(func(t *rapid.T) resourceSpec {
		depth := rapid.IntRange(0, 2).Draw(t, "depth")
		r := resourceSpec{
			family:  rapid.SampledFrom(specFamilies).Draw(t, "family"),
			name:    rapid.SampledFrom(names).Draw(t, "name"),
			key:     genKey().Draw(t, "key"),
			action:  rapid.SampledFrom(actions).Draw(t, "action"),
			value:   rapid.SampledFrom(valueStates).Draw(t, "value"),
			marked:  rapid.IntRange(0, 3).Draw(t, "marked") == 0,
			target:  rapid.SampledFrom(targetStates).Draw(t, "target"),
			subject: "repo:acme/" + genSubject().Draw(t, "subject"),
			poolID:  rapid.SampledFrom([]string{"github", "gitlab"}).Draw(t, "pool"),
		}
		for i := 0; i < depth; i++ {
			r.module = append(r.module, rapid.SampledFrom([]string{"ci", "child"}).Draw(t, "module"))
			r.keys = append(r.keys, genKey().Draw(t, "moduleKey"))
		}
		return r
	})
}

type planSpec struct {
	resources []resourceSpec
	complete  *bool
	errored   *bool
	junk      bool // unrecognised members at every level
}

func genPlan() *rapid.Generator[planSpec] {
	return rapid.Custom(func(t *rapid.T) planSpec {
		names := rapid.SliceOfNDistinct(rapid.SampledFrom([]string{"a", "b", "c", "d", "e"}), 1, 5, func(s string) string { return s }).Draw(t, "names")
		specs := rapid.SliceOfN(genResource(names), 2, 8).Draw(t, "resources")
		p := planSpec{resources: distinctAddresses(specs), junk: rapid.Bool().Draw(t, "junk")}
		if rapid.Bool().Draw(t, "statesComplete") {
			p.complete = ptr(rapid.Bool().Draw(t, "complete"))
		}
		if rapid.Bool().Draw(t, "statesErrored") {
			p.errored = ptr(rapid.Bool().Draw(t, "errored"))
		}
		return p
	})
}

func ptr[T any](v T) *T { return &v }

// distinctAddresses keeps the first spec of each address, since a plan
// lists an instance once, and gives every instance of one resource block
// the block's target state, since the configuration describes a block by
// one expression.
func distinctAddresses(specs []resourceSpec) []resourceSpec {
	seen := map[string]bool{}
	blocks := map[string]targetState{}
	var out []resourceSpec
	for _, s := range specs {
		if seen[s.address()] {
			continue
		}
		seen[s.address()] = true
		block := strings.Join(s.module, "/") + ":" + s.typeName() + "." + s.name
		if first, ok := blocks[block]; ok {
			s.target = first
		} else {
			blocks[block] = s.target
		}
		out = append(out, s)
	}
	return out
}

const (
	federated = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
	poolPath  = "projects/123456789012/locations/global/workloadIdentityPools/"
)

func policyFor(subject string) string {
	return `{"Statement":[{"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":` + strconv.Quote(subject) + `}},"Effect":"Allow","Principal":{"Federated":"` + federated + `"}}],"Version":"2012-10-17"}`
}

// referencedType is the type of the resource a target attribute
// references when it is unknown; referencedName names it after the spec,
// so that two specs never share a referenced resource with different
// instance counts.
func (r resourceSpec) referencedName() string {
	return strings.ReplaceAll(strings.TrimPrefix(r.typeName(), "google_service_account_iam_"), "azure", "") + "_" + r.name
}

func (r resourceSpec) referencedType() string {
	if r.family == entraCred {
		return "azuread_application_registration"
	}
	if r.family == armCred {
		return "azurerm_user_assigned_identity"
	}
	return "google_service_account"
}

func (r resourceSpec) targetAttribute() string {
	switch r.family {
	case entraCred:
		return "application_id"
	case armCred:
		return "user_assigned_identity_id"
	case googleMember, googleBinding, googlePolicy:
		return "service_account_id"
	}
	return ""
}

// values builds the attribute object of a resource, the unknown marks and
// the sensitive marks beside it, as the plan writes them. state is true
// for the values representation, where an unknown cannot be marked and
// the deep and top unknown states fall back to the known value.
func (r resourceSpec) values(state bool) (values, unknown, sensitiveMarks map[string]any) {
	values, unknown, sensitiveMarks = map[string]any{"id": "id-" + r.name}, map[string]any{}, map[string]any{}
	if !state {
		delete(values, "id")
		unknown["id"] = true
	}
	set := func(name string, v any) {
		switch r.value {
		case absent:
		case null:
			values[name] = nil
		default:
			values[name] = v
		}
	}
	switch r.family {
	case awsRole:
		set("assume_role_policy", policyFor(r.subject))
		values["name"] = r.name
		if state {
			values["arn"] = "arn:aws:iam::123456789012:role/" + r.name
		} else {
			unknown["arn"] = true
		}
	case entraCred, armCred:
		set("subject", r.subject)
		values["issuer"] = "https://token.actions.githubusercontent.com"
		audiences := "audiences"
		if r.family == armCred {
			audiences = "audience"
			values["name"] = r.name
		} else {
			values["display_name"] = r.name
		}
		values[audiences] = []any{"api://AzureADTokenExchange"}
		sensitiveMarks[audiences] = []any{false}
		if r.value == unknownDeep && !state {
			values[audiences] = []any{nil}
			unknown[audiences] = []any{true}
		}
	case googleProvider:
		set("attribute_condition", "assertion.sub == '"+r.subject+"'")
		values["attribute_mapping"] = map[string]any{"google.subject": "assertion.sub"}
		values["oidc"] = []any{map[string]any{"allowed_audiences": []any{"aud-a", "aud-b"}, "issuer_uri": "https://token.actions.githubusercontent.com"}}
		values["aws"], values["saml"], values["x509"] = []any{}, []any{}, []any{}
		values["disabled"] = nil
		values["workload_identity_pool_id"] = r.poolID
		sensitiveMarks["oidc"] = []any{map[string]any{"allowed_audiences": []any{false, false}}}
		if r.value == unknownDeep && !state {
			values["oidc"] = []any{map[string]any{"allowed_audiences": []any{"aud-a", nil}, "issuer_uri": "https://token.actions.githubusercontent.com"}}
			unknown["oidc"] = []any{map[string]any{"allowed_audiences": []any{false, true}}}
		}
		if state {
			values["name"] = poolPath + r.poolID + "/providers/" + r.name
			values["state"] = "ACTIVE"
		} else {
			unknown["name"], unknown["state"] = true, true
		}
	case googleMember:
		set("member", "principalSet://iam.googleapis.com/"+poolPath+r.poolID+"/*")
		values["role"] = "roles/iam.workloadIdentityUser"
		values["condition"] = []any{}
	case googleBinding:
		set("members", []any{"principalSet://iam.googleapis.com/" + poolPath + r.poolID + "/*", "user:" + r.name + "@acme.example"})
		values["role"] = "roles/iam.workloadIdentityUser"
		values["condition"] = []any{}
		sensitiveMarks["members"] = []any{false, false}
		if r.value == unknownDeep && !state {
			values["members"] = []any{"principalSet://iam.googleapis.com/" + poolPath + r.poolID + "/*", nil}
			unknown["members"] = []any{false, true}
		}
	case googlePolicy:
		set("policy_data", `{"bindings":[{"members":["principalSet://iam.googleapis.com/`+poolPath+r.poolID+`/*"],"role":"roles/iam.workloadIdentityUser"}]}`)
	case unmapped:
		set("assume_role_policy_document", map[string]any{"Version": "2012-10-17"})
	case unrelated:
		values["url"] = "https://token.actions.githubusercontent.com"
	}
	if r.value == unknownTop && !state {
		delete(values, r.admission())
		unknown[r.admission()] = true
	}
	if r.value == unknownDeep && !state && r.nested() == "" {
		delete(values, r.admission())
		unknown[r.admission()] = true
	}
	if r.marked {
		sensitiveMarks[r.admission()] = true
	}
	if attr := r.targetAttribute(); attr != "" {
		switch {
		case r.target == targetKnown || state:
			values[attr] = "target-" + r.name
		default:
			unknown[attr] = true
		}
	}
	return values, unknown, sensitiveMarks
}

// expressions is the configuration block for the resource: the target
// attribute's references when it is unknown, and the admission attribute's.
func (r resourceSpec) expressions() map[string]any {
	e := map[string]any{}
	if attr := r.targetAttribute(); attr != "" && r.target != targetKnown {
		switch r.target {
		case targetUnresolved:
			e[attr] = map[string]any{"references": []any{"var.target"}}
		default:
			e[attr] = map[string]any{"references": []any{r.referencedType() + "." + r.referencedName() + ".id", r.referencedType() + "." + r.referencedName()}}
		}
	}
	e[r.admission()] = map[string]any{"references": []any{"local.sub", "var.org"}}
	return e
}

// junkify adds an unrecognised member to every object of a value whose
// members are properties. The objects keyed by names the author chose,
// module_calls, provider_config and a map attribute, gain none: a new key
// there is a new call or a new entry, not a new property, and the format
// promises nothing about it.
func junkify(v any) any {
	return junkifyUnder("", v)
}

func junkifyUnder(key string, v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		if key != "module_calls" && key != "provider_config" && key != "attribute_mapping" {
			out["zz_future"] = []any{1, "two", map[string]any{"three": true}}
		}
		for k, val := range x {
			out[k] = junkifyUnder(k, val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = junkifyUnder("", val)
		}
		return out
	}
	return v
}

// referencedInstances lists the instances the plan holds of the resource
// a spec's unknown target references.
func (r resourceSpec) referencedInstances() []map[string]any {
	if r.targetAttribute() == "" {
		return nil
	}
	prefix := ""
	if m := r.moduleAddress(); m != "" {
		prefix = m + "."
	}
	base := prefix + r.referencedType() + "." + r.referencedName()
	change := func(address string) map[string]any {
		rc := map[string]any{"address": address, "mode": "managed", "type": r.referencedType(), "name": r.referencedName(),
			"change": map[string]any{"actions": []any{"create"}, "before": nil, "after": map[string]any{"display_name": "t"}, "after_unknown": map[string]any{"id": true}, "before_sensitive": false, "after_sensitive": map[string]any{}}}
		if m := r.moduleAddress(); m != "" {
			rc["module_address"] = m
		}
		return rc
	}
	switch r.target {
	case targetOne:
		return []map[string]any{change(base)}
	case targetMany:
		return []map[string]any{change(base + `["x"]`), change(base + `["y"]`)}
	}
	return nil
}

// json renders the spec as a plan document: a change for every listed
// resource, a prior state holding every resource that existed before the
// plan, and the configuration.
func (p planSpec) json() []byte {
	var changes []any
	configs := map[string]map[string]any{} // module path -> configuration module
	root := map[string]any{"resources": []any{}, "module_calls": map[string]any{}}
	configs[""] = root
	var moduleOf func(path []string) map[string]any
	moduleOf = func(path []string) map[string]any {
		key := strings.Join(path, "/")
		if m, ok := configs[key]; ok {
			return m
		}
		parent := moduleOf(path[:len(path)-1])
		m := map[string]any{"resources": []any{}, "module_calls": map[string]any{}}
		parent["module_calls"].(map[string]any)[path[len(path)-1]] = map[string]any{"source": "./" + path[len(path)-1], "module": m}
		configs[key] = m
		return m
	}
	seenTargets, configured := map[string]bool{}, map[string]bool{}
	var prior []resourceSpec
	for _, r := range p.resources {
		if existed(r.action) {
			prior = append(prior, r)
		}
		if inChanges(r.action) {
			// The before value is what the prior state holds, fully known, as
			// Terraform records it; the after value is what the plan will send.
			before, _, beforeMarks := r.values(true)
			after, unknown, afterMarks := r.values(false)
			change := map[string]any{"actions": []any{r.action}, "before": nil, "after": after, "after_unknown": unknown, "before_sensitive": false, "after_sensitive": afterMarks}
			switch r.action {
			case "delete", "forget":
				change["before"], change["after"], change["after_unknown"], change["before_sensitive"], change["after_sensitive"] = before, nil, map[string]any{}, beforeMarks, false
			case "update", "no-op":
				change["before"], change["before_sensitive"] = before, beforeMarks
			case "replace":
				change["actions"], change["before"], change["before_sensitive"] = []any{"delete", "create"}, before, beforeMarks
			case "create-forget":
				change["actions"], change["before"], change["before_sensitive"] = []any{"create", "forget"}, before, beforeMarks
			}
			rc := map[string]any{"address": r.address(), "mode": "managed", "type": r.typeName(), "name": r.name, "change": change}
			if m := r.moduleAddress(); m != "" {
				rc["module_address"] = m
			}
			changes = append(changes, rc)
		}
		for _, inst := range r.referencedInstances() {
			if address := inst["address"].(string); !seenTargets[address] {
				seenTargets[address] = true
				changes = append(changes, inst)
			}
		}
		// The configuration lists a resource once, whatever its instances.
		m := moduleOf(r.module)
		if configKey := strings.Join(r.module, "/") + ":" + r.typeName() + "." + r.name; !configured[configKey] {
			configured[configKey] = true
			m["resources"] = append(m["resources"].([]any), map[string]any{"address": r.typeName() + "." + r.name, "mode": "managed", "type": r.typeName(), "name": r.name, "expressions": r.expressions()})
		}
	}
	doc := map[string]any{"format_version": "1.2", "terraform_version": "1.15.5", "planned_values": map[string]any{"root_module": map[string]any{}}, "configuration": map[string]any{"root_module": root}}
	if changes != nil {
		doc["resource_changes"] = changes
	}
	if prior != nil {
		doc["prior_state"] = map[string]any{"format_version": "1.0", "values": map[string]any{"root_module": valuesTree(prior)}}
	}
	if p.complete != nil {
		doc["complete"] = *p.complete
	}
	if p.errored != nil {
		doc["errored"] = *p.errored
	}
	if p.junk {
		doc = junkify(doc).(map[string]any)
	}
	return marshal(doc)
}

// valuesTree renders resources as the values representation's module
// tree, nested in child_modules as Terraform writes them.
func valuesTree(resources []resourceSpec) map[string]any {
	type module struct {
		address   string
		resources []any
		children  map[string]*module
	}
	root := &module{children: map[string]*module{}}
	for _, r := range resources {
		m := root
		for i, name := range r.module {
			key := name + r.keys[i]
			child, ok := m.children[key]
			if !ok {
				address := "module." + key
				if m.address != "" {
					address = m.address + "." + address
				}
				child = &module{address: address, children: map[string]*module{}}
				m.children[key] = child
			}
			m = child
		}
		values, _, sensitiveMarks := r.values(true)
		res := map[string]any{"address": r.address(), "mode": "managed", "type": r.typeName(), "name": r.name, "values": values, "sensitive_values": sensitiveMarks}
		if r.key != "" {
			res["index"] = strings.Trim(r.key, `[]"`)
		}
		m.resources = append(m.resources, res)
	}
	var render func(m *module) map[string]any
	render = func(m *module) map[string]any {
		out := map[string]any{"resources": m.resources}
		if m.address != "" {
			out["address"] = m.address
		}
		var children []any
		for _, key := range mapKeys(m.children) {
			children = append(children, render(m.children[key]))
		}
		if children != nil {
			out["child_modules"] = children
		}
		return out
	}
	return render(root)
}

// stateJSON renders the spec's resources as a state document.
func (p planSpec) stateJSON() []byte {
	doc := map[string]any{"format_version": "1.0", "terraform_version": "1.15.5", "values": map[string]any{"root_module": valuesTree(p.resources)}}
	if p.junk {
		doc = junkify(doc).(map[string]any)
	}
	return marshal(doc)
}

func marshal(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	return b.Bytes()
}

// widened is what the spec says about the grants of one object of a
// resource: whether the reader must widen every grant of it to
// everything, and why. Only the after side carries unknown marks; the
// before side, the prior state and a state are fully known, so only an
// absent or null required attribute widens them.
func (r resourceSpec) widened(from string) (bool, string) {
	switch {
	case from == "after" && (r.value == unknownTop || r.value == unknownDeep):
		return true, KnownAfterApply
	case (r.value == absent || r.value == null) && r.required():
		return true, AbsentAttribute
	}
	return false, ""
}

// fateOf is the reader's fact about an object read from a side other
// than after, "" when there is none.
func fateOf(action, from string) string {
	switch {
	case from == "prior_state":
		return NoChangeListed
	case from == "before" && action == "delete":
		return PlannedDelete
	case from == "before":
		return PlannedForget
	}
	return ""
}

// valueText is a fragment of the admission value that a quote or a record
// of it would carry, and a redaction must not.
func (r resourceSpec) valueText() string {
	switch r.family {
	case googleMember, googleBinding, googlePolicy:
		return "principalSet://"
	}
	return r.subject
}

// checkSensitive holds every grant of an object to the mark: the
// sensitive-value anomaly is on the grant if and only if the attribute is
// marked, and a marked value that was read is neither quoted nor carried
// as evidence, only its digest.
func checkSensitive(t *rapid.T, r resourceSpec, from string, g trust.Grant, raw []byte) {
	a := anomalyOf(g, SensitiveValue)
	if (a.Kind != "") != r.marked || (r.marked && a.Source != r.address()) {
		t.Fatalf("%s (%s, marked %v): sensitive-value %+v\n%s", r.address(), from, r.marked, a, raw)
	}
	if !r.marked {
		return
	}
	widen, _ := r.widened(from)
	if widen != strings.Contains(a.Message, "no value of") {
		t.Fatalf("%s (%s): widened %v yet the sensitive sentence is %q\n%s", r.address(), from, widen, a.Message, raw)
	}
	if widen {
		return
	}
	body := string(g.Provenance[0].Bytes)
	if strings.Contains(body, r.valueText()) || strings.Contains(string(g.Source), r.valueText()) || !strings.Contains(body, `"sha256"`) {
		t.Fatalf("%s (%s): a sensitive value is quoted: bytes %s source %s\n%s", r.address(), from, body, g.Source, raw)
	}
}

// required reports whether the admission attribute the value state
// applies to is one Terraform requires, so that absent or null cannot
// mean unset.
func (r resourceSpec) required() bool {
	return r.family != googleProvider
}

// TestTotalityOverArbitraryBytes: neither reader panics on any input,
// a refusal comes with no document, and a document read twice states the
// same grants byte for byte.
func TestTotalityOverArbitraryBytes(t *testing.T) {
	parsed, refusedCount := 0, 0
	rapid.Check(t, func(t *rapid.T) {
		for _, raw := range [][]byte{rapid.SliceOfN(rapid.Byte(), 0, 64).Draw(t, "bytes"), damaged(t, genPlan().Draw(t, "plan").json())} {
			p, err := ParsePlan(raw, "input")
			if err != nil {
				refusedCount++
				if p.Resources != nil || p.Unread != nil || p.FormatVersion != "" {
					t.Fatalf("a refusal came with a document: %+v", p)
				}
			} else {
				parsed++
				first, again := p.Grants(clock, vocabulary), p.Grants(clock, vocabulary)
				if !bytes.Equal(render(first), render(again)) {
					t.Fatalf("read differently twice: %s", raw)
				}
			}
			s, err := ParseState(raw, "input")
			if err != nil {
				refusedCount++
				if s.Resources != nil || s.Unread != nil {
					t.Fatalf("a refusal came with a document: %+v", s)
				}
			} else {
				parsed++
				if !bytes.Equal(render(s.Grants(clock, vocabulary)), render(s.Grants(clock, vocabulary))) {
					t.Fatalf("read differently twice: %s", raw)
				}
			}
		}
	})
	if parsed == 0 || refusedCount == 0 {
		t.Fatalf("parsed %d, refused %d; both must be positive", parsed, refusedCount)
	}
	t.Logf("parsed %d, refused %d", parsed, refusedCount)
}

// damaged returns a plan with one byte changed, dropped or added, so that
// the totality property sees documents that are nearly right.
func damaged(t *rapid.T, raw []byte) []byte {
	out := slices.Clone(raw)
	at := rapid.IntRange(0, len(out)-1).Draw(t, "at")
	switch rapid.IntRange(0, 2).Draw(t, "damage") {
	case 0:
		out[at] = rapid.Byte().Draw(t, "byte")
	case 1:
		out = slices.Delete(out, at, at+1)
	default:
		out = slices.Insert(out, at, rapid.Byte().Draw(t, "byte"))
	}
	return out
}

// TestUnknownBeforeAfter: every object the reader reads of a listed or
// unlisted resource yields grants, and each grant answers to the spec.
// An attribute marked unknown anywhere beneath its path makes every grant
// of the object admit everything, declared, with the known-after-apply
// anomaly naming the mark, whatever after holds; a required attribute
// absent or null and unmarked does the same with the absent-attribute
// anomaly; an object read from before or from the prior state carries
// the fact that says why, and is never widened by a mark, since neither
// side carries one; a mark on a sensitive attribute is stated on every
// grant and redacts the quote; and an object whose attributes are all
// known yields at least one grant that is not widened.
func TestUnknownBeforeAfter(t *testing.T) {
	seen := map[string]int{}
	enoughExamples(t, func(t *rapid.T) {
		spec := genPlan().Draw(t, "plan")
		raw := spec.json()
		p, err := ParsePlan(raw, "plan.json")
		if err != nil {
			t.Fatalf("%v\n%s", err, raw)
		}
		listedOnce := map[string]int{}
		for _, res := range p.Resources {
			listedOnce[res.Address]++
		}
		by := groupByObject(t, p.Grants(clock, vocabulary))
		for _, r := range spec.resources {
			if !r.family.mapped() {
				if listedOnce[r.address()] != 0 {
					t.Fatalf("%s is listed; the table does not name it", r.address())
				}
				continue
			}
			if listedOnce[r.address()] != 1 {
				t.Fatalf("%s is listed %d times\n%s", r.address(), listedOnce[r.address()], raw)
			}
			seen["action "+r.action]++
			for _, from := range objects(r.action) {
				gs := by[r.address()+"|"+from]
				if len(gs) == 0 {
					t.Fatalf("%s (%s) yields no grant\n%s", r.address(), from, raw)
				}
				widen, kind := r.widened(from)
				seen[string(r.value)+" "+from+" "+strconv.FormatBool(widen)]++
				fate := fateOf(r.action, from)
				for _, g := range gs {
					has := slices.ContainsFunc(g.Anomalies, func(a trust.Anomaly) bool { return a.Kind == kind && a.Source == r.address() })
					switch {
					case widen && (!g.Admits.IsTop() || g.Exact() || !has):
						t.Fatalf("%s (%s, %s): admits %s exact %v anomalies %v; want everything, inexact, with %s\n%s", r.address(), from, r.value, g.Admits, g.Exact(), g.Anomalies, kind, raw)
					case !widen && slices.ContainsFunc(g.Anomalies, func(a trust.Anomaly) bool {
						return (a.Kind == KnownAfterApply || a.Kind == AbsentAttribute) && a.Source == r.address()
					}):
						t.Fatalf("%s (%s, %s): widened without cause: %v\n%s", r.address(), from, r.value, g.Anomalies, raw)
					}
					for _, f := range []string{PlannedDelete, PlannedForget, NoChangeListed} {
						if (anomalyOf(g, f).Kind != "") != (f == fate) {
							t.Fatalf("%s (%s): fate %s stated %v, want %q\n%s", r.address(), from, f, anomalyOf(g, f).Kind != "", fate, raw)
						}
					}
					if widen && kind == KnownAfterApply && r.value == unknownDeep && r.nested() != "" {
						a := anomalyOf(g, KnownAfterApply)
						if !strings.Contains(a.Construct, r.nested()) {
							t.Fatalf("%s: the mark one level down is not named: construct %q\n%s", r.address(), a.Construct, raw)
						}
						seen["nested named"]++
					}
					checkSensitive(t, r, from, g, raw)
					if r.marked {
						seen["marked "+from+" "+strconv.FormatBool(widen)]++
					}
				}
			}
		}
	})
	for _, want := range []string{"known after false", "unknown after true", "unknown-nested after true", "absent after true", "null after true", "absent after false", "null after false", "unknown before false", "unknown prior_state false", "known before false", "known prior_state false", "absent before true", "absent prior_state true", "nested named", "marked after true", "marked after false", "marked before false", "marked prior_state false", "action forget", "action create-forget", "action unlisted", "action delete"} {
		if seen[want] == 0 {
			t.Errorf("the generator never produced %q", want)
		}
	}
	t.Logf("saw %v", seen)
}

// twice runs a property over two runs of rapid's checks, so that the
// rarest shapes the guards count are drawn with enough room to appear.
// enoughExamples runs a property over six hundred examples rather than
// rapid's hundred. The rarest combination the guard in TestUnknownBeforeAfter
// insists on, an unlisted resource with an absent required attribute, is
// drawn about 3.5 times per hundred examples (measured over thirty runs on
// 2026-09-20: a mean of 7.1 per two hundred, a minimum of 3); at two
// hundred a run failed to draw it once in about six hundred, and at six
// hundred the chance is below one in a billion, so the guard says the
// generator went stale, never that the dice did.
func enoughExamples(t *testing.T, property func(*rapid.T)) {
	t.Helper()
	for range 6 {
		rapid.Check(t, property)
	}
}

func anomalyOf(g trust.Grant, kind string) trust.Anomaly {
	for _, a := range g.Anomalies {
		if a.Kind == kind {
			return a
		}
	}
	return trust.Anomaly{}
}

func groupByAddress(t *rapid.T, gs []trust.Grant) map[string][]trust.Grant {
	by := map[string][]trust.Grant{}
	for _, g := range gs {
		address := paramsIn(t, g)["address"].(string)
		by[address] = append(by[address], g)
	}
	return by
}

// groupByObject groups grants by the address and the side of the plan
// their first record names: "address|after", "address|before" or
// "address|prior_state".
func groupByObject(t *rapid.T, gs []trust.Grant) map[string][]trust.Grant {
	by := map[string][]trust.Grant{}
	for _, g := range gs {
		params := paramsIn(t, g)
		from, _ := params["from"].(string)
		key := params["address"].(string) + "|" + from
		by[key] = append(by[key], g)
	}
	return by
}

func paramsIn(t *rapid.T, g trust.Grant) map[string]any {
	var params map[string]any
	if err := json.Unmarshal([]byte(g.Provenance[0].Params), &params); err != nil {
		t.Fatalf("%v", err)
	}
	return params
}

// TestAbsentInStateIsUnknown: in a state, every instance the table names
// yields a grant, wherever it sits in the module tree; a required attribute
// absent or null is read as everything with the absent-attribute anomaly,
// and a known one is not; a mark is stated and redacts the quote.
func TestAbsentInStateIsUnknown(t *testing.T) {
	seen := map[string]int{}
	enoughExamples(t, func(t *rapid.T) {
		spec := genPlan().Draw(t, "plan")
		raw := spec.stateJSON()
		s, err := ParseState(raw, "state.json")
		if err != nil {
			t.Fatalf("%v\n%s", err, raw)
		}
		examined := map[string]bool{}
		for _, r := range s.Resources {
			examined[r.Address] = true
		}
		by := groupByAddress(t, s.Grants(clock, vocabulary))
		for _, r := range spec.resources {
			if !r.family.mapped() {
				if examined[r.address()] {
					t.Fatalf("%s is examined; the table does not name it", r.address())
				}
				continue
			}
			if !examined[r.address()] {
				t.Fatalf("%s is not examined\n%s", r.address(), raw)
			}
			seen["depth "+strconv.Itoa(len(r.module))]++
			gs := by[r.address()]
			if len(gs) == 0 {
				t.Fatalf("%s yields no grant\n%s", r.address(), raw)
			}
			widen, kind := r.widened("")
			seen[string(r.value)+" "+strconv.FormatBool(widen)]++
			for _, g := range gs {
				has := slices.ContainsFunc(g.Anomalies, func(a trust.Anomaly) bool { return a.Kind == kind && a.Source == r.address() })
				if widen && (!g.Admits.IsTop() || g.Exact() || !has) {
					t.Fatalf("%s (%s): admits %s exact %v anomalies %v\n%s", r.address(), r.value, g.Admits, g.Exact(), g.Anomalies, raw)
				}
				if !widen && slices.ContainsFunc(g.Anomalies, func(a trust.Anomaly) bool { return a.Kind == AbsentAttribute || a.Kind == KnownAfterApply }) {
					t.Fatalf("%s (%s): widened without cause: %v\n%s", r.address(), r.value, g.Anomalies, raw)
				}
				for _, f := range []string{PlannedDelete, PlannedForget, NoChangeListed} {
					if anomalyOf(g, f).Kind != "" {
						t.Fatalf("%s: a state states the plan's fact %s\n%s", r.address(), f, raw)
					}
				}
				checkSensitive(t, r, "", g, raw)
				if r.marked {
					seen["marked "+strconv.FormatBool(widen)]++
				}
			}
		}
	})
	for _, want := range []string{"depth 0", "depth 1", "depth 2", "absent true", "null true", "absent false", "known false", "unknown false", "marked true", "marked false"} {
		if seen[want] == 0 {
			t.Errorf("the generator never produced %q", want)
		}
	}
	t.Logf("saw %v", seen)
}

// TestUnknownMembersAreIgnored: an unrecognised member at any level of a
// plan or a state changes nothing the reader says, so the readers stay
// forward-compatible with the minor versions HashiCorp promises. Junk
// includes a mark on an attribute the table does not read, which must not
// widen anything.
func TestUnknownMembersAreIgnored(t *testing.T) {
	compared := 0
	rapid.Check(t, func(t *rapid.T) {
		spec := genPlan().Draw(t, "plan")
		spec.junk = false
		clean, junky := spec, spec
		junky.junk = true
		for _, docs := range [][2][]byte{{clean.json(), junky.json()}, {clean.stateJSON(), junky.stateJSON()}} {
			var a, b []byte
			for i, raw := range docs {
				var gs []trust.Grant
				if bytes.Contains(raw, []byte(`"planned_values"`)) {
					p, err := ParsePlan(raw, "input")
					if err != nil {
						t.Fatalf("%v", err)
					}
					gs = p.Grants(clock, vocabulary)
				} else {
					s, err := ParseState(raw, "input")
					if err != nil {
						t.Fatalf("%v", err)
					}
					gs = s.Grants(clock, vocabulary)
				}
				if i == 0 {
					a = render(gs)
				} else {
					b = render(gs)
				}
			}
			compared++
			if !bytes.Equal(a, b) {
				t.Fatalf("junk changed the reading:\n%s\n---\n%s", a, b)
			}
		}
	})
	if compared == 0 {
		t.Fatalf("compared nothing")
	}
	t.Logf("compared %d document pairs", compared)
}

// TestTargetResolution: a credential or binding whose target attribute is
// known names the target by its value; unknown and referencing a resource
// the plan holds one instance of, by that instance's address; otherwise by
// its own address, and in both unknown cases with the target-after-apply
// anomaly saying which. The value, when known, is in the record's Params
// under the attribute's name.
func TestTargetResolution(t *testing.T) {
	seen := map[string]int{}
	rapid.Check(t, func(t *rapid.T) {
		spec := genPlan().Draw(t, "plan")
		raw := spec.json()
		p, err := ParsePlan(raw, "plan.json")
		if err != nil {
			t.Fatalf("%v", err)
		}
		by := groupByObject(t, p.Grants(clock, vocabulary))
		for _, r := range spec.resources {
			if r.targetAttribute() == "" || !r.family.mapped() {
				continue
			}
			for _, from := range objects(r.action) {
				// An object read from before or from the prior state has
				// every attribute known, the target's included.
				state := r.target
				if from != "after" {
					state = targetKnown
				}
				seen[string(state)]++
				prefix := ""
				if m := r.moduleAddress(); m != "" {
					prefix = m + "."
				}
				want := map[targetState]string{targetKnown: "target-" + r.name, targetOne: prefix + r.referencedType() + "." + r.referencedName(), targetMany: r.address(), targetUnresolved: r.address()}[state]
				for _, g := range by[r.address()+"|"+from] {
					if g.Target.ID != want {
						t.Fatalf("%s (%s, %s): target %q, want %q\n%s", r.address(), from, state, g.Target.ID, want, raw)
					}
					if has := slices.ContainsFunc(g.Anomalies, func(a trust.Anomaly) bool { return a.Kind == TargetAfterApply }); has != (state != targetKnown) {
						t.Fatalf("%s (%s): target-after-apply %v", r.address(), state, has)
					}
					named, _ := paramsIn(t, g)[r.targetAttribute()].(string)
					if state == targetKnown && named != want || state != targetKnown && named != "" {
						t.Fatalf("%s (%s): params name the target as %q\n%s", r.address(), state, named, raw)
					}
				}
			}
		}
	})
	// The wanted states are listed here rather than read from targetStates,
	// so that a generator that stops drawing one is caught by this guard
	// instead of quietly shrinking it.
	for _, want := range []targetState{targetKnown, targetOne, targetMany, targetUnresolved} {
		if seen[string(want)] == 0 {
			t.Errorf("the generator never produced %q", want)
		}
	}
	t.Logf("saw %v", seen)
}

// TestPlanFlags: a plan marked incomplete or errored says so on every
// grant; one that states neither, or states them clean, says nothing.
func TestPlanFlags(t *testing.T) {
	seen := map[string]int{}
	rapid.Check(t, func(t *rapid.T) {
		spec := genPlan().Draw(t, "plan")
		p, err := ParsePlan(spec.json(), "plan.json")
		if err != nil {
			t.Fatalf("%v", err)
		}
		partial := (spec.complete != nil && !*spec.complete) || (spec.errored != nil && *spec.errored)
		seen[strconv.FormatBool(partial)]++
		for _, g := range p.Grants(clock, vocabulary) {
			if has := slices.ContainsFunc(g.Anomalies, func(a trust.Anomaly) bool { return a.Kind == PlanIncomplete }); has != partial {
				t.Fatalf("plan-incomplete %v with complete %v errored %v", has, spec.complete, spec.errored)
			}
		}
	})
	if seen["true"] == 0 || seen["false"] == 0 {
		t.Fatalf("saw %v", seen)
	}
}

// TestGeneratorStalenessGuard guards the guards: every family, action,
// value state, target state, module depth and instance key must be drawn,
// and the subjects must vary, or the properties above pass over documents
// that never exercise them.
func TestGeneratorStalenessGuard(t *testing.T) {
	seen := map[string]int{}
	subjects := map[string]bool{}
	rapid.Check(t, func(t *rapid.T) {
		spec := genPlan().Draw(t, "plan")
		if spec.junk {
			seen["junk"]++
		}
		if spec.complete != nil {
			seen["complete "+strconv.FormatBool(*spec.complete)]++
		}
		if spec.errored != nil {
			seen["errored "+strconv.FormatBool(*spec.errored)]++
		}
		for _, r := range spec.resources {
			seen["family "+string(r.family)]++
			seen["action "+r.action]++
			seen["value "+string(r.value)]++
			seen["marked "+strconv.FormatBool(r.marked)]++
			seen["target "+string(r.target)]++
			seen["depth "+strconv.Itoa(len(r.module))]++
			seen["key "+r.key]++
			for _, k := range r.keys {
				seen["module key "+k]++
			}
			subjects[r.subject] = true
			if r.value == unknownDeep && r.nested() != "" {
				seen["nested mark"]++
			}
		}
	})
	var want []string
	for _, f := range specFamilies {
		want = append(want, "family "+string(f))
	}
	for _, a := range actions {
		want = append(want, "action "+a)
	}
	for _, v := range valueStates {
		want = append(want, "value "+string(v))
	}
	for _, s := range targetStates {
		want = append(want, "target "+string(s))
	}
	want = append(want, "depth 0", "depth 1", "depth 2", "key ", "key [0]", `key ["a"]`, `key ["b.c"]`, "module key [1]", "junk", "complete true", "complete false", "errored true", "errored false", "nested mark", "marked true", "marked false")
	for _, w := range want {
		if seen[w] == 0 {
			t.Errorf("the generator never produced %q", w)
		}
	}
	if len(subjects) < 32 {
		t.Errorf("the generator drew %d distinct subjects; fewer than 32 means it has collapsed", len(subjects))
	}
	t.Logf("drew %v and %d subjects", seen, len(subjects))
}
