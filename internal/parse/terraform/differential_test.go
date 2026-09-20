package terraform

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/parse/azure"
	"github.com/CloudArq-net/cloudarq/internal/parse/gcp"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// grantsDir holds the conformance triples: one logical grant in every
// provider's syntax, which the cloud parsers are judged against.
const grantsDir = "../../../testdata/grants"

// meaning renders what a grant means and nothing about where it came
// from: target, issuer, effect, the canonical admitted set, the caveats,
// and the anomalies with the reader's own removed, told by their kind and
// their source, the instance's address or the artefact, since the
// parsers spell malformed the same way. Source and Provenance are left
// out: the reader's Source is a built document or a redaction where the
// parser's is the customer's bytes, and only the reader attaches records.
func meaning(g trust.Grant, address string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "target %s %s\nissuer %s\neffect %s\nadmits %s\n", g.Target.Kind, g.Target.ID, g.Issuer, g.Effect, g.Admits)
	for _, c := range g.Admits.Caveats() {
		fmt.Fprintf(&b, "caveat %s|%s|%s\n", c.Claim, c.Reason, c.Source)
	}
	for _, a := range g.Anomalies {
		if readerAnomaly(a, address) {
			continue
		}
		fmt.Fprintf(&b, "anomaly %s|%s|%s|%s|%s\n", a.Kind, a.Claim, a.Construct, a.Message, a.Source)
	}
	return b.String()
}

func meanings(gs []trust.Grant, address string) string {
	var out []string
	for _, g := range gs {
		out = append(out, meaning(g, address))
	}
	return strings.Join(out, "---\n")
}

// roleValue is what the plan or state says about one aws_iam_role
// object, read here by the test's own hand so that the differential does
// not rest on the reader's reading: the after value of a change unless
// its actions are exactly delete or forget; the before value of a delete
// and of any change that forgets; the prior state's value of a managed
// resource the plan lists no change for.
type roleValue struct {
	address   string
	deposed   string
	from      string // after, before, prior_state, or "" in a state
	policy    string
	known     bool // the value is stated and not marked unknown
	sensitive bool
}

// instance names one object of the plan: the address, the deposed key
// when the change is to a deposed object, and the side it was read from.
func (r roleValue) instance() string { return r.address + "|" + r.deposed + "|" + r.from }

// grantsByInstance groups grants by the address, deposed key and side
// their first record names.
func grantsByInstance(t testing.TB, gs []trust.Grant) map[string][]trust.Grant {
	t.Helper()
	by := map[string][]trust.Grant{}
	for _, g := range gs {
		params := paramsOf(t, g.Provenance[0])
		deposed, _ := params["deposed"].(string)
		from, _ := params["from"].(string)
		key := params["address"].(string) + "|" + deposed + "|" + from
		by[key] = append(by[key], g)
	}
	return by
}

func rolesInPlan(t testing.TB, raw []byte) []roleValue {
	t.Helper()
	var p struct {
		ResourceChanges []struct {
			Address string `json:"address"`
			Type    string `json:"type"`
			Deposed string `json:"deposed"`
			Change  struct {
				Actions         []string                   `json:"actions"`
				Before          map[string]json.RawMessage `json:"before"`
				After           map[string]json.RawMessage `json:"after"`
				AfterUnknown    map[string]json.RawMessage `json:"after_unknown"`
				BeforeSensitive json.RawMessage            `json:"before_sensitive"`
				AfterSensitive  json.RawMessage            `json:"after_sensitive"`
			} `json:"change"`
		} `json:"resource_changes"`
		PriorState struct {
			Values struct {
				RootModule valuesModule `json:"root_module"`
			} `json:"values"`
		} `json:"prior_state"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("%v", err)
	}
	var out []roleValue
	listed := map[string]bool{}
	for _, rc := range p.ResourceChanges {
		listed[rc.Address] = true
		if rc.Type != "aws_iam_role" {
			continue
		}
		actions := rc.Change.Actions
		read := func(side map[string]json.RawMessage, from string, sensitive json.RawMessage) {
			r := roleValue{address: rc.Address, deposed: rc.Deposed, from: from}
			if v, ok := side["assume_role_policy"]; ok && json.Unmarshal(v, &r.policy) == nil && r.policy != "" {
				r.known = from == "before" || string(rc.Change.AfterUnknown["assume_role_policy"]) != "true"
			}
			var marks map[string]json.RawMessage
			if json.Unmarshal(sensitive, &marks) == nil && string(marks["assume_role_policy"]) == "true" {
				r.sensitive = true
			}
			out = append(out, r)
		}
		if !slices.Equal(actions, []string{"delete"}) && !slices.Equal(actions, []string{"forget"}) {
			read(rc.Change.After, "after", rc.Change.AfterSensitive)
		}
		if slices.Contains(actions, "forget") || slices.Equal(actions, []string{"delete"}) {
			read(rc.Change.Before, "before", rc.Change.BeforeSensitive)
		}
	}
	for _, r := range rolesInValues(p.PriorState.Values.RootModule) {
		if !listed[r.address] {
			r.from = "prior_state"
			out = append(out, r)
		}
	}
	return out
}

type valuesModule struct {
	Resources []struct {
		Address         string                     `json:"address"`
		Mode            string                     `json:"mode"`
		Type            string                     `json:"type"`
		Values          map[string]json.RawMessage `json:"values"`
		SensitiveValues map[string]json.RawMessage `json:"sensitive_values"`
	} `json:"resources"`
	ChildModules []valuesModule `json:"child_modules"`
}

// rolesInValues walks a values representation for its managed roles.
func rolesInValues(m valuesModule) []roleValue {
	var out []roleValue
	for _, r := range m.Resources {
		if r.Type != "aws_iam_role" || r.Mode == "data" {
			continue
		}
		v := roleValue{address: r.Address, sensitive: string(r.SensitiveValues["assume_role_policy"]) == "true"}
		if raw, ok := r.Values["assume_role_policy"]; ok && json.Unmarshal(raw, &v.policy) == nil && v.policy != "" {
			v.known = true
		}
		out = append(out, v)
	}
	for _, c := range m.ChildModules {
		out = append(out, rolesInValues(c)...)
	}
	return out
}

func rolesInState(t testing.TB, raw []byte) []roleValue {
	t.Helper()
	var s struct {
		Values struct {
			RootModule valuesModule `json:"root_module"`
		} `json:"values"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("%v", err)
	}
	return rolesInValues(s.Values.RootModule)
}

// TestDifferentialAWS: for every aws_iam_role object of the corpus whose
// policy the document states, the reader's grants mean exactly what the
// AWS parser makes of the same string handed to it directly, the parser's
// facts about the document carried on each and the reader's own
// anomalies removed; a policy the parser projects no statement from
// means one grant admitting nothing with those facts; and for every
// object the document does not state, the reader yields one grant
// admitting everything. Nothing the reader adds may change what the
// policy means.
func TestDifferentialAWS(t *testing.T) {
	compared, widened, empty := 0, 0, 0
	for _, d := range documents(t) {
		if _, no := refused[d.name]; no || d.kind == "tfstate" {
			continue
		}
		var roles []roleValue
		if d.kind == "plan" {
			roles = rolesInPlan(t, d.raw)
		} else {
			roles = rolesInState(t, d.raw)
		}
		if len(roles) == 0 {
			continue
		}
		by := grantsByInstance(t, mustGrants(t, d.name))
		for _, r := range roles {
			got := by[r.instance()]
			if !r.known {
				widened++
				if len(got) != 1 || !got[0].Admits.IsTop() || got[0].Exact() {
					t.Errorf("%s: %s is not stated, yet the reader yields %s", d.name, r.address, meanings(got, r.address))
				}
				continue
			}
			compared++
			doc, err := aws.ParseTrustPolicy([]byte(r.policy))
			if err != nil {
				t.Fatalf("%s: %s: %v", d.name, r.address, err)
			}
			want := doc.Grants(role(r.address), vocabulary)
			if len(want) == 0 {
				empty++
				want = []trust.Grant{{Target: role(r.address), Admits: eval.Nothing(), Effect: trust.Allow}}
			}
			for i := range want {
				want[i].Anomalies = append(want[i].Anomalies, doc.Anomalies...)
			}
			if x, y := meanings(got, r.address), meanings(want, r.address); x != y {
				t.Errorf("%s: %s\n--- reader ---\n%s\n--- parser ---\n%s", d.name, r.address, x, y)
			}
			if r.sensitive {
				for _, g := range got {
					if strings.Contains(string(g.Source), "Statement") {
						t.Errorf("%s: %s is sensitive and quoted: %s", d.name, r.address, g.Source)
					}
				}
			}
		}
	}
	if compared < 35 || widened < 5 || empty < 1 {
		t.Fatalf("compared %d roles and saw %d widened and %d empty; the corpus has more", compared, widened, empty)
	}
	t.Logf("compared %d roles, %d widened, %d empty", compared, widened, empty)
}

// TestDifferentialConformance: the conformance triples, written as plans,
// read to what the cloud parsers make of the API documents of the same
// cases. The plans are the recorded AWS plan, whose strings are the
// provider's normalisation of the very files, and the hand-written Azure
// and GCP plans; the comparison is non-tautological because the reader
// builds the Azure and GCP documents from attributes and the AWS strings
// are another rendering of the policy.
func TestDifferentialConformance(t *testing.T) {
	cases, err := os.ReadDir(grantsDir)
	if err != nil {
		t.Fatalf("%v", err)
	}
	type side struct {
		plan, file string
		address    func(n string) string
		target     trust.TargetRef
		parse      func(raw []byte, target trust.TargetRef) ([]trust.Grant, error)
	}
	sides := []side{
		{"01-aws-plan", "aws.json", func(n string) string { return `aws_iam_role.conformance["` + n + `"]` }, trust.TargetRef{}, func(raw []byte, target trust.TargetRef) ([]trust.Grant, error) {
			d, err := aws.ParseTrustPolicy(raw)
			if err != nil {
				return nil, err
			}
			return d.Grants(target, vocabulary), nil
		}},
		{"11-azure-conformance", "azure.json", func(n string) string {
			return `azuread_application_federated_identity_credential.conformance["` + n + `"]`
		}, existingApp, func(raw []byte, target trust.TargetRef) ([]trust.Grant, error) {
			c, err := azure.ParseFederatedCredential(raw)
			if err != nil {
				return nil, err
			}
			return c.Grants(target), nil
		}},
		{"12-gcp-conformance", "gcp.json", func(n string) string {
			return `google_iam_workload_identity_pool_provider.conformance["` + n + `"]`
		}, trust.TargetRef{}, func(raw []byte, target trust.TargetRef) ([]trust.Grant, error) {
			p, err := gcp.ParseProvider(raw)
			if err != nil {
				return nil, err
			}
			return p.Grants(target), nil
		}},
	}
	// The Azure cases a classic credential cannot state: the azuread
	// provider's schema has subject Required and no expression argument,
	// so a claimsMatchingExpression case has no plan; two cases have no
	// Azure document at all.
	inexpressible := map[string]string{"02": "no azure.json", "03": "claimsMatchingExpression", "05": "claimsMatchingExpression", "06": "no azure.json", "07": "claimsMatchingExpression"}
	compared := 0
	for _, s := range sides {
		by, _ := grantsByAddress(t, mustGrants(t, s.plan))
		for _, c := range cases {
			n := c.Name()[:2]
			raw, err := os.ReadFile(filepath.Join(grantsDir, c.Name(), s.file))
			got := by[s.address(n)]
			if s.file == "azure.json" {
				why, no := inexpressible[n]
				if no && why == "no azure.json" && err == nil {
					t.Errorf("%s has an azure.json; the table says it has none", c.Name())
				}
				if no && why == "claimsMatchingExpression" && !strings.Contains(string(raw), "claimsMatchingExpression") {
					t.Errorf("%s: the table says the Azure document is an expression; it is not", c.Name())
				}
				if no {
					if len(got) != 0 {
						t.Errorf("%s: the Azure plan states a grant for a case Terraform's azuread provider cannot express", c.Name())
					}
					continue
				}
			}
			if err != nil {
				t.Fatalf("%s: %v", c.Name(), err)
			}
			target := s.target
			if target.ID == "" {
				target = got[0].Target
			}
			want, err := s.parse(raw, target)
			if err != nil {
				t.Fatalf("%s/%s: %v", c.Name(), s.file, err)
			}
			compared++
			if x, y := meanings(got, s.address(n)), meanings(want, s.address(n)); x != y {
				t.Errorf("%s/%s\n--- reader ---\n%s\n--- parser ---\n%s", c.Name(), s.file, x, y)
			}
		}
	}
	if compared != 7+2+7 {
		t.Fatalf("compared %d case documents, want 16", compared)
	}
	t.Logf("compared %d case documents", compared)
}

// TestDifferentialState: a state document's provider builds to the API
// document that the pinned bytes say, and means what the GCP parser makes
// of that document, bindings included.
func TestDifferentialState(t *testing.T) {
	by, _ := grantsByAddress(t, mustGrants(t, "05-gcp-state"))
	provider, err := gcp.ParseProvider([]byte(stateProviderDoc))
	if err != nil {
		t.Fatalf("%v", err)
	}
	own := by["google_iam_workload_identity_pool_provider.github"]
	if x, y := meanings(own, "google_iam_workload_identity_pool_provider.github"), meanings(provider.Grants(wipp("google_iam_workload_identity_pool_provider.github")), "google_iam_workload_identity_pool_provider.github"); x != y {
		t.Errorf("provider\n--- reader ---\n%s\n--- parser ---\n%s", x, y)
	}
	members, err := gcp.ParseMembers([]byte(ciBindingDocument))
	if err != nil {
		t.Fatalf("%v", err)
	}
	bound, ok := provider.Bind(members[0], runnerAccount)
	if !ok {
		t.Fatalf("the parser does not bind the subject member")
	}
	if x, y := meaning(by["google_service_account_iam_binding.ci"][0], "google_service_account_iam_binding.ci"), meaning(bound, "google_service_account_iam_binding.ci"); x != y {
		t.Errorf("binding\n--- reader ---\n%s\n--- parser ---\n%s", x, y)
	}
	if _, ok := provider.Bind(members[1], runnerAccount); ok {
		t.Fatalf("the parser binds the user member; the reader's unbound grant would be untested")
	}
}
