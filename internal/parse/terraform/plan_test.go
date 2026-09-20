package terraform

import (
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/evidence"
	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// corpusDir holds one directory per case: the plan or state JSON, the
// grants.json rendering the reader must produce for it, and a rationale
// saying where the document came from and why the rendering is right.
const corpusDir = "../../../testdata/terraform"

const (
	github     trust.IssuerRef = "https://token.actions.githubusercontent.com"
	gitlab     trust.IssuerRef = "https://gitlab.com"
	awsSTS     trust.IssuerRef = "aws:sts"
	stsAud                     = `aud="sts.amazonaws.com"`
	entraAud                   = `aud="api://AzureADTokenExchange"`
	poolAud                    = `aud="https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github/providers/github"`
	nameAud                    = `aud=("//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github/providers/github" | "https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github/providers/github")`
	gitlabAud                  = `aud="https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/gitlab/providers/gitlab"`
	everything                 = "{}"
)

// clock is the caller's clock: the reader never reads one.
var clock = time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)

// vocabulary knows the two issuers the corpus names, as the registry will.
var vocabulary = aws.LowercaseVocabulary(github, gitlab)

// document is the one JSON file a case holds and which reader it is for.
type document struct {
	name string
	raw  []byte
	kind string // "plan", "state" or "tfstate"
}

func documents(t testing.TB) []document {
	t.Helper()
	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		t.Fatalf("%v", err)
	}
	var docs []document
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var found []document
		for _, file := range []struct{ name, kind string }{{"plan.json", "plan"}, {"state.json", "state"}, {"terraform.tfstate.json", "tfstate"}} {
			raw, err := os.ReadFile(filepath.Join(corpusDir, e.Name(), file.name))
			if err == nil {
				found = append(found, document{e.Name(), raw, file.kind})
			}
		}
		if len(found) != 1 {
			t.Fatalf("%s holds %d documents, want exactly one of plan.json, state.json or terraform.tfstate.json", e.Name(), len(found))
		}
		docs = append(docs, found[0])
	}
	if len(docs) == 0 {
		t.Fatalf("no cases under %s; the corpus is empty", corpusDir)
	}
	return docs
}

func caseDocument(t testing.TB, name string) document {
	t.Helper()
	for _, d := range documents(t) {
		if d.name == name {
			return d
		}
	}
	t.Fatalf("no case %s", name)
	return document{}
}

// grantsOf reads a case's document with the reader its file name says and
// returns the Grants, or the refusal.
func grantsOf(t testing.TB, d document) ([]trust.Grant, error) {
	t.Helper()
	switch d.kind {
	case "plan":
		p, err := ParsePlan(d.raw, d.name+"/plan.json")
		if err != nil {
			return nil, err
		}
		return p.Grants(clock, vocabulary), nil
	case "state":
		s, err := ParseState(d.raw, d.name+"/state.json")
		if err != nil {
			return nil, err
		}
		return s.Grants(clock, vocabulary), nil
	}
	_, err := ParseState(d.raw, d.name+"/terraform.tfstate.json")
	return nil, err
}

func mustGrants(t testing.TB, name string) []trust.Grant {
	t.Helper()
	gs, err := grantsOf(t, caseDocument(t, name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return gs
}

// rendering is the grants.json form of a Grant: every field, the evidence
// bytes and the customer's bytes as strings so that the file pins them byte
// for byte.
type rendering struct {
	Target     targetRendering   `json:"target"`
	Issuer     trust.IssuerRef   `json:"issuer"`
	Effect     trust.Effect      `json:"effect"`
	Admits     string            `json:"admits"`
	Exact      bool              `json:"exact"`
	Caveats    []caveatRendering `json:"caveats"`
	Anomalies  []trust.Anomaly   `json:"anomalies"`
	Provenance []recordRendering `json:"provenance"`
	Source     string            `json:"source"`
}

type targetRendering struct {
	Kind trust.TargetKind `json:"kind"`
	ID   string           `json:"id"`
}

type caveatRendering struct {
	Claim  trust.ClaimKey `json:"claim"`
	Reason string         `json:"reason"`
	Source string         `json:"source"`
}

type recordRendering struct {
	API       string          `json:"api"`
	Params    string          `json:"params"`
	Status    evidence.Status `json:"status"`
	SHA256    string          `json:"sha256"`
	FetchedAt time.Time       `json:"fetched_at"`
	Bytes     string          `json:"bytes"`
}

func render(gs []trust.Grant) []byte {
	out := make([]rendering, 0, len(gs))
	for _, g := range gs {
		r := rendering{
			Target:    targetRendering{g.Target.Kind, g.Target.ID},
			Issuer:    g.Issuer,
			Effect:    g.Effect,
			Admits:    g.Admits.String(),
			Exact:     g.Exact(),
			Caveats:   []caveatRendering{},
			Anomalies: []trust.Anomaly{},
			Source:    string(g.Source),
		}
		for _, c := range g.Admits.Caveats() {
			r.Caveats = append(r.Caveats, caveatRendering{c.Claim, c.Reason, c.Source})
		}
		r.Anomalies = append(r.Anomalies, g.Anomalies...)
		for _, rec := range g.Provenance {
			r.Provenance = append(r.Provenance, recordRendering{rec.API, rec.Params, rec.Status, rec.SHA256, rec.FetchedAt, string(rec.Bytes)})
		}
		out = append(out, r)
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
	return b.Bytes()
}

// refused lists the cases the readers must refuse, with the sentence each
// refusal carries.
var refused = map[string]string{
	"07-unsupported-version": `format_version "2.0" is major version 2`,
	"08-raw-tfstate":         "this is a raw state file; run terraform show -json and pass its output",
}

// TestGoldenCorpus: every case renders to its grants.json byte for byte,
// every refused case is refused with its sentence, and the invariants no
// Terraform-sourced Grant may break hold over the whole corpus. Set
// UPDATE_GOLDEN=1 to rewrite the renderings after reading the diff.
func TestGoldenCorpus(t *testing.T) {
	examined, rendered := 0, 0
	for _, d := range documents(t) {
		examined++
		if _, err := os.Stat(filepath.Join(corpusDir, d.name, "rationale.md")); err != nil {
			t.Errorf("%s has no rationale: %v", d.name, err)
		}
		gs, err := grantsOf(t, d)
		if want, no := refused[d.name]; no {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s: refusal %v, want one containing %q", d.name, err, want)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", d.name, err)
			continue
		}
		rendered++
		got := render(gs)
		path := filepath.Join(corpusDir, d.name, "grants.json")
		if os.Getenv("UPDATE_GOLDEN") == "1" {
			if err := os.WriteFile(path, got, 0o644); err != nil {
				t.Fatalf("%v", err)
			}
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("%s: %v", d.name, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: the rendering differs from grants.json\n--- got ---\n%s\n--- want ---\n%s", d.name, firstDifference(got, want), firstDifference(want, got))
		}
		checkInvariants(t, d, gs)
	}
	if examined != len(refused)+rendered || rendered == 0 {
		t.Fatalf("examined %d cases, rendered %d, refused %d", examined, rendered, len(refused))
	}
	t.Logf("examined %d cases, rendered %d, refused %d", examined, rendered, len(refused))
}

// firstDifference shows the lines around the first line on which two
// renderings differ, so a failure is readable.
func firstDifference(a, b []byte) string {
	x, y := strings.Split(string(a), "\n"), strings.Split(string(b), "\n")
	for i := range x {
		if i >= len(y) || x[i] != y[i] {
			return strings.Join(x[max(0, i-3):min(len(x), i+8)], "\n")
		}
	}
	return "(no differing line; the shorter rendering ends first)"
}

// checkInvariants is what every Grant the reader produces must satisfy,
// whatever the document.
func checkInvariants(t *testing.T, d document, gs []trust.Grant) {
	t.Helper()
	origin := "terraform/" + d.kind
	for i, g := range gs {
		where := d.name + " grant " + itoa(i)
		if g.Target.ID == "" || g.Target.Kind == "" {
			t.Errorf("%s: target %+v names nothing", where, g.Target)
		}
		if g.Effect == "" {
			t.Errorf("%s: no effect", where)
		}
		if len(g.Provenance) == 0 {
			t.Errorf("%s: no evidence", where)
		}
		for _, r := range g.Provenance {
			if r.API != origin || r.Status != evidence.StatusOK || r.FetchedAt != clock || len(r.Bytes) == 0 || r.SHA256 == "" {
				t.Errorf("%s: record %+v is not a terraform record with a body", where, r)
			}
			if !json.Valid([]byte(r.Params)) {
				t.Errorf("%s: params %q are not JSON", where, r.Params)
			}
		}
		if !slices.ContainsFunc(g.Anomalies, func(a trust.Anomaly) bool { return a.Kind == TerraformOrigin }) {
			t.Errorf("%s: no terraform-origin anomaly", where)
		}
		for _, a := range g.Anomalies {
			if a.Construct == "" || a.Message == "" || a.Source == "" {
				t.Errorf("%s: anomaly %+v names no construct, message or source", where, a)
			}
		}
		caveats := g.Admits.Caveats()
		for _, term := range g.Admits.Terms() {
			for k, s := range term {
				if eval.IsUnknown(s) && !slices.ContainsFunc(caveats, func(c eval.Caveat) bool { return c.Claim == k || c.Claim == "" }) {
					t.Errorf("%s: %s is Unknown without a caveat", where, k)
				}
			}
		}
		if g.Admits.IsEmpty() && !slices.ContainsFunc(g.Anomalies, func(a trust.Anomaly) bool {
			return a.Kind == NoMembers || a.Kind == NoStatements || a.Kind == aws.NotAnAssumeAction
		}) {
			t.Errorf("%s: admits nothing with no anomaly proving the emptiness", where)
		}
		if len(g.Source) == 0 {
			t.Errorf("%s: no Source", where)
		}
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

// grantsByAddress groups a case's grants by the address their first record
// names, in first-seen order.
func grantsByAddress(t testing.TB, gs []trust.Grant) (map[string][]trust.Grant, []string) {
	t.Helper()
	by := map[string][]trust.Grant{}
	var order []string
	for _, g := range gs {
		address, _ := paramsOf(t, g.Provenance[0])["address"].(string)
		if _, seen := by[address]; !seen {
			order = append(order, address)
		}
		by[address] = append(by[address], g)
	}
	return by, order
}

func paramsOf(t testing.TB, r evidence.Record) map[string]any {
	t.Helper()
	var params map[string]any
	if err := json.Unmarshal([]byte(r.Params), &params); err != nil {
		t.Fatalf("params %q: %v", r.Params, err)
	}
	return params
}

// want is what one Grant of a case must say: its target, issuer, admitted
// set and exactness, and every anomaly kind in order. Messages are pinned
// for the reader's own sentences by TestSentences.
type want struct {
	target trust.TargetRef
	issuer trust.IssuerRef
	admits string
	exact  bool
	kinds  []string
}

func role(address string) trust.TargetRef {
	return trust.TargetRef{Kind: "role", ID: address}
}

func wipp(address string) trust.TargetRef {
	return trust.TargetRef{Kind: "workloadIdentityPoolProvider", ID: address}
}

func serviceAccount(id string) trust.TargetRef {
	return trust.TargetRef{Kind: "serviceAccount", ID: id}
}

func application(id string) trust.TargetRef {
	return trust.TargetRef{Kind: "application", ID: id}
}

var (
	deployAccount  = serviceAccount("projects/acme-prod/serviceAccounts/deploy@acme-prod.iam.gserviceaccount.com")
	runnerAccount  = serviceAccount("projects/acme-prod/serviceAccounts/ci-runner@acme-prod.iam.gserviceaccount.com")
	releaseAccount = serviceAccount("projects/acme-prod/serviceAccounts/release@acme-prod.iam.gserviceaccount.com")
	existingApp    = application("/applications/6b1e6c7e-0f1a-4d2b-9c3d-8e4f5a6b7c8d")
	plannedApp     = application("azuread_application_registration.infra")
	runnerIdentity = trust.TargetRef{Kind: "userAssignedIdentity", ID: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/ci/providers/Microsoft.ManagedIdentity/userAssignedIdentities/runner"}
)

func exact(target trust.TargetRef, issuer trust.IssuerRef, admits string, kinds ...string) want {
	return want{target, issuer, admits, true, append(kinds, TerraformOrigin)}
}

func widened(target trust.TargetRef, issuer trust.IssuerRef, kinds ...string) want {
	return want{target, issuer, everything, false, append(kinds, TerraformOrigin)}
}

// The grants each case must state, by the address of the resource each
// came from, in the order the reader yields them. A case's grants are
// judged only through this table and the byte-exact rendering; an address
// the table names that yields nothing, or a grant the table does not
// name, is a failure.
var expectations = map[string]map[string][]want{
	"01-aws-plan": {
		"aws_iam_role.collapsed":                      {exact(role("aws_iam_role.collapsed"), github, `{sub=like:"repo:*"}`)},
		`aws_iam_role.conformance["01"]`:              {exact(role(`aws_iam_role.conformance["01"]`), github, `{`+stsAud+`, sub="repo:acme/infra:ref:refs/heads/main"}`)},
		`aws_iam_role.conformance["02"]`:              {exact(role(`aws_iam_role.conformance["02"]`), github, `{`+stsAud+`, sub=like:"repo:acme/infra:*"}`)},
		`aws_iam_role.conformance["03"]`:              {exact(role(`aws_iam_role.conformance["03"]`), github, `{`+stsAud+`, repository_owner_id="123456", sub=like:"repo:acme/*"}`)},
		`aws_iam_role.conformance["04"]`:              {exact(role(`aws_iam_role.conformance["04"]`), github, `{`+stsAud+`, sub="repo:acme@123456/infra@456789:ref:refs/heads/main"}`)},
		`aws_iam_role.conformance["05"]`:              {exact(role(`aws_iam_role.conformance["05"]`), github, `{`+stsAud+`, repository_id="456789"}`)},
		`aws_iam_role.conformance["06"]`:              {exact(role(`aws_iam_role.conformance["06"]`), github, `{`+stsAud+`}`)},
		`aws_iam_role.conformance["07"]`:              {{role(`aws_iam_role.conformance["07"]`), github, `{` + stsAud + `, repository_id="456789", sub=?("ForAllValues:StringLike")}`, false, []string{trust.Unmodelled, TerraformOrigin}}},
		"aws_iam_role.counted[0]":                     {exact(role("aws_iam_role.counted[0]"), github, `{sub="repo:acme/infra:environment:env-0"}`)},
		"aws_iam_role.counted[1]":                     {exact(role("aws_iam_role.counted[1]"), github, `{sub="repo:acme/infra:environment:env-1"}`)},
		"aws_iam_role.deferred":                       {widened(role("aws_iam_role.deferred"), "", KnownAfterApply)},
		"aws_iam_role.fromdoc":                        {exact(role("aws_iam_role.fromdoc"), github, `{sub=(like:"repo:acme/*" | like:"repo:acme/infra:*")}`)},
		"aws_iam_role.heredoc":                        {exact(role("aws_iam_role.heredoc"), github, `{sub="repo:acme/infra:ref:refs/heads/main"}`)},
		"aws_iam_role.known":                          {exact(role("aws_iam_role.known"), github, `{`+stsAud+`, sub=like:"repo:acme/*"}`)},
		"aws_iam_role.marked":                         {exact(role("aws_iam_role.marked"), github, `{sub="repo:acme/secret:ref:refs/heads/main"}`, SensitiveValue)},
		"aws_iam_role.transformed":                    {widened(role("aws_iam_role.transformed"), "", KnownAfterApply, RenderedDocument)},
		"aws_iam_role.unknown":                        {widened(role("aws_iam_role.unknown"), "", KnownAfterApply)},
		`module.ci[0].aws_iam_role.runner["build"]`:   {exact(role(`module.ci[0].aws_iam_role.runner["build"]`), github, `{sub="repo:acme/infra:environment:build"}`)},
		`module.ci[0].aws_iam_role.runner["release"]`: {exact(role(`module.ci[0].aws_iam_role.runner["release"]`), github, `{sub="repo:acme/infra:environment:release"}`)},
		`module.ci[1].aws_iam_role.runner["build"]`:   {exact(role(`module.ci[1].aws_iam_role.runner["build"]`), github, `{sub="repo:acme/infra:environment:build"}`)},
		`module.ci[1].aws_iam_role.runner["release"]`: {exact(role(`module.ci[1].aws_iam_role.runner["release"]`), github, `{sub="repo:acme/infra:environment:release"}`)},
	},
	"02-gcp-plan": {
		"google_iam_workload_identity_pool_provider.aws":               {exact(wipp("google_iam_workload_identity_pool_provider.aws"), awsSTS, `{aws:principalaccount="123456789012"}`)},
		"google_iam_workload_identity_pool_provider.disabled":          {{wipp("google_iam_workload_identity_pool_provider.disabled"), github, everything, false, []string{"default-audience", "provider-disabled", TerraformOrigin}}},
		"google_iam_workload_identity_pool_provider.known":             {exact(wipp("google_iam_workload_identity_pool_provider.known"), github, `{`+poolAud+`, sub="repo:acme/infra:ref:refs/heads/main"}`)},
		"google_iam_workload_identity_pool_provider.nested_unknown":    {widened(wipp("google_iam_workload_identity_pool_provider.nested_unknown"), github, KnownAfterApply)},
		"google_iam_workload_identity_pool_provider.unknown_condition": {widened(wipp("google_iam_workload_identity_pool_provider.unknown_condition"), gitlab, KnownAfterApply)},
		// Every provider of the member's pool is nameless before apply, so
		// each is read as bound with the parser's doubt; the aws provider
		// is of another pool and is not; a provider known only after apply
		// binds as everything with its own reason.
		"google_service_account_iam_binding.ci": {
			{runnerAccount, github, `{sub="repo:acme/infra:ref:refs/heads/main"}`, false, []string{"default-audience", "provider-disabled", trust.Unmodelled, trust.Unmodelled, TerraformOrigin}},
			{runnerAccount, github, `{` + poolAud + `, sub="repo:acme/infra:ref:refs/heads/main"}`, false, []string{trust.Unmodelled, trust.Unmodelled, TerraformOrigin}},
			widened(runnerAccount, github, KnownAfterApply),
			widened(runnerAccount, gitlab, KnownAfterApply),
			widened(runnerAccount, "", UnboundMember),
		},
		"google_service_account_iam_binding.self": {
			{runnerAccount, github, everything, false, []string{"default-audience", "provider-disabled", trust.Unmodelled, trust.Unmodelled, TerraformOrigin}},
			{runnerAccount, github, `{` + poolAud + `, repository="acme/web", sub="repo:acme/infra:ref:refs/heads/main"}`, false, []string{trust.Unmodelled, TerraformOrigin}},
			widened(runnerAccount, github, KnownAfterApply),
			widened(runnerAccount, gitlab, KnownAfterApply),
			widened(runnerAccount, "", UnboundMember),
		},
		"google_service_account_iam_member.deploy": {
			{serviceAccount("google_service_account.deploy"), github, everything, false, []string{"default-audience", "provider-disabled", trust.Unmodelled, trust.Unmodelled, TargetAfterApply, TerraformOrigin}},
			{serviceAccount("google_service_account.deploy"), github, `{` + poolAud + `, repository="acme/infra", sub="repo:acme/infra:ref:refs/heads/main"}`, false, []string{trust.Unmodelled, TargetAfterApply, TerraformOrigin}},
			widened(serviceAccount("google_service_account.deploy"), github, KnownAfterApply, TargetAfterApply),
			widened(serviceAccount("google_service_account.deploy"), gitlab, KnownAfterApply, TargetAfterApply),
		},
		"google_service_account_iam_policy.release": {
			{releaseAccount, github, everything, false, []string{"default-audience", "provider-disabled", trust.Unmodelled, TerraformOrigin}},
			{releaseAccount, github, `{` + poolAud + `, sub="repo:acme/infra:ref:refs/heads/main"}`, false, []string{trust.Unmodelled, TerraformOrigin}},
			widened(releaseAccount, github, KnownAfterApply),
			widened(releaseAccount, gitlab, KnownAfterApply),
		},
	},
	"03-azure-plan": {
		"azuread_application_federated_identity_credential.existing":        {exact(existingApp, gitlab, `{`+entraAud+`, sub="project_path:acme/web:ref_type:branch:ref:main"}`)},
		"azuread_application_federated_identity_credential.immutable":       {exact(plannedApp, github, `{`+entraAud+`, sub="repo:acme@123456/infra@456789:ref:refs/heads/main"}`, TargetAfterApply)},
		"azuread_application_federated_identity_credential.main":            {exact(plannedApp, github, `{`+entraAud+`, sub="repo:acme/infra:ref:refs/heads/main"}`, TargetAfterApply)},
		"azuread_application_federated_identity_credential.unknown_subject": {widened(existingApp, github, KnownAfterApply)},
		"azurerm_federated_identity_credential.runner":                      {exact(runnerIdentity, github, `{`+entraAud+`, sub="repo:acme/infra:environment:prod"}`)},
	},
	"04-aws-state": {
		"aws_iam_role.counted[0]":                     {exact(role("aws_iam_role.counted[0]"), github, `{`+stsAud+`, sub="repo:acme/infra:environment:env-0"}`, UnreadResource)},
		"aws_iam_role.counted[1]":                     {exact(role("aws_iam_role.counted[1]"), github, `{`+stsAud+`, sub="repo:acme/infra:environment:env-1"}`, UnreadResource)},
		"aws_iam_role.deploy":                         {exact(role("aws_iam_role.deploy"), github, `{`+stsAud+`, sub="repo:acme/infra:ref:refs/heads/main"}`, UnreadResource)},
		"aws_iam_role.legacy":                         {widened(role("aws_iam_role.legacy"), "", AbsentAttribute, UnreadResource)},
		"aws_iam_role.marked":                         {exact(role("aws_iam_role.marked"), github, `{`+stsAud+`, sub="repo:acme/secret:ref:refs/heads/main"}`, SensitiveValue, UnreadResource)},
		"aws_iam_role.nulled":                         {widened(role("aws_iam_role.nulled"), "", AbsentAttribute, UnreadResource)},
		`module.ci[0].aws_iam_role.runner["build"]`:   {exact(role(`module.ci[0].aws_iam_role.runner["build"]`), github, `{`+stsAud+`, sub="repo:acme/infra:environment:build"}`, UnreadResource)},
		`module.ci[0].aws_iam_role.runner["release"]`: {exact(role(`module.ci[0].aws_iam_role.runner["release"]`), github, `{`+stsAud+`, sub="repo:acme/infra:environment:release"}`, UnreadResource)},
		`module.ci[1].aws_iam_role.runner["build"]`:   {exact(role(`module.ci[1].aws_iam_role.runner["build"]`), github, `{`+stsAud+`, sub="repo:acme/web:environment:build"}`, UnreadResource)},
		"module.ci[1].module.inner.aws_iam_role.deep": {exact(role("module.ci[1].module.inner.aws_iam_role.deep"), github, `{sub=like:"repo:acme/deep:*"}`, UnreadResource)},
	},
	"05-gcp-state": {
		"google_iam_workload_identity_pool_provider.github": {exact(wipp("google_iam_workload_identity_pool_provider.github"), github, `{`+nameAud+`, repository_owner_id="123456"}`, "default-audience", UnreadResource)},
		"google_iam_workload_identity_pool_provider.gitlab": {exact(wipp("google_iam_workload_identity_pool_provider.gitlab"), gitlab, `{`+gitlabAud+`, namespace_path="acme"}`, UnreadResource)},
		"google_service_account_iam_binding.ci": {
			{runnerAccount, github, `{` + nameAud + `, repository_owner_id="123456", sub="repo:acme/infra:ref:refs/heads/main"}`, false, []string{"default-audience", trust.Unmodelled, UnreadResource, TerraformOrigin}},
			widened(runnerAccount, "", UnboundMember, UnreadResource),
		},
		"google_service_account_iam_member.deploy": {exact(deployAccount, github, `{`+nameAud+`, repository="acme/infra", repository_owner_id="123456"}`, "default-audience", UnreadResource)},
		"google_service_account_iam_policy.release": {
			exact(releaseAccount, gitlab, `{`+gitlabAud+`, namespace_path="acme"}`, UnreadResource),
			widened(releaseAccount, "", UnboundMember, UnreadResource),
		},
	},
	"06-aws-plan-actions": {
		"aws_iam_role.kept": {exact(role("aws_iam_role.kept"), github, `{`+stsAud+`, sub="repo:acme/infra:ref:refs/heads/main"}`, PlanIncomplete)},
		"aws_iam_role.old": {
			exact(role("aws_iam_role.old"), github, `{`+stsAud+`, sub="repo:acme/old:*"}`, PlannedDelete, PlanIncomplete),
			exact(role("aws_iam_role.old"), github, `{`+stsAud+`, sub="repo:acme/old:*"}`, PlannedDelete, PlanIncomplete),
		},
		"aws_iam_role.replaced":  {exact(role("aws_iam_role.replaced"), github, `{`+stsAud+`, sub="repo:acme/replaced:v2"}`, PlanIncomplete)},
		"aws_iam_role.rotated":   {widened(role("aws_iam_role.rotated"), "", KnownAfterApply, PlanIncomplete)},
		"aws_iam_role.forgotten": {exact(role("aws_iam_role.forgotten"), github, `{`+stsAud+`, sub="repo:acme/legacy:ref:refs/heads/main"}`, PlannedForget, PlanIncomplete)},
		// The created object first, from after, then the forgotten one, from
		// before: both exist once the plan is applied.
		"aws_iam_role.reborn": {
			exact(role("aws_iam_role.reborn"), github, `{`+stsAud+`, sub="repo:acme/reborn:environment:prod"}`, PlanIncomplete),
			exact(role("aws_iam_role.reborn"), github, `{`+stsAud+`, sub="repo:acme/reborn:ref:refs/heads/main"}`, PlannedForget, PlanIncomplete),
		},
		"aws_iam_role.hollow":     {{role("aws_iam_role.hollow"), "", "∅", true, []string{NoStatements, aws.Malformed, PlanIncomplete, TerraformOrigin}}},
		"aws_iam_role.untargeted": {exact(role("aws_iam_role.untargeted"), github, `{`+stsAud+`, sub=like:"repo:acme/untargeted:*"}`, NoChangeListed, PlanIncomplete)},
	},
	"09-empty-state": {},
	"10-empty-plan":  {},
	"11-azure-conformance": {
		`azuread_application_federated_identity_credential.conformance["01"]`: {exact(existingApp, github, `{`+entraAud+`, sub="repo:acme/infra:ref:refs/heads/main"}`)},
		`azuread_application_federated_identity_credential.conformance["04"]`: {exact(existingApp, github, `{`+entraAud+`, sub="repo:acme@123456/infra@456789:ref:refs/heads/main"}`)},
	},
	"12-gcp-conformance": {
		`google_iam_workload_identity_pool_provider.conformance["01"]`: {exact(wipp(`google_iam_workload_identity_pool_provider.conformance["01"]`), github, `{`+poolAud+`, sub="repo:acme/infra:ref:refs/heads/main"}`)},
		`google_iam_workload_identity_pool_provider.conformance["02"]`: {exact(wipp(`google_iam_workload_identity_pool_provider.conformance["02"]`), github, `{`+poolAud+`, sub=like:"repo:acme/infra:*"}`)},
		`google_iam_workload_identity_pool_provider.conformance["03"]`: {exact(wipp(`google_iam_workload_identity_pool_provider.conformance["03"]`), github, `{`+poolAud+`, repository_owner_id="123456", sub=like:"repo:acme/*"}`)},
		`google_iam_workload_identity_pool_provider.conformance["04"]`: {exact(wipp(`google_iam_workload_identity_pool_provider.conformance["04"]`), github, `{`+poolAud+`, sub="repo:acme@123456/infra@456789:ref:refs/heads/main"}`)},
		`google_iam_workload_identity_pool_provider.conformance["05"]`: {exact(wipp(`google_iam_workload_identity_pool_provider.conformance["05"]`), github, `{`+poolAud+`, repository_id="456789"}`)},
		`google_iam_workload_identity_pool_provider.conformance["06"]`: {exact(wipp(`google_iam_workload_identity_pool_provider.conformance["06"]`), github, `{`+poolAud+`}`)},
		`google_iam_workload_identity_pool_provider.conformance["07"]`: {exact(wipp(`google_iam_workload_identity_pool_provider.conformance["07"]`), github, `{`+poolAud+`, repository_id="456789", sub=like:"repo:acme/infra:*"}`)},
	},
	"13-errored-plan": {
		"aws_iam_role.deploy": {exact(role("aws_iam_role.deploy"), github, `{sub="repo:acme/infra:ref:refs/heads/main"}`, PlanIncomplete)},
	},
	"14-refresh-only-plan": {
		"aws_iam_role.deploy":           {exact(role("aws_iam_role.deploy"), github, `{`+stsAud+`, sub="repo:acme/infra:ref:refs/heads/main"}`, NoChangeListed, UnreadResource)},
		"aws_iam_role.marked":           {exact(role("aws_iam_role.marked"), github, `{`+stsAud+`, sub="repo:acme/secret:ref:refs/heads/main"}`, SensitiveValue, NoChangeListed, UnreadResource)},
		"aws_iam_role.counted[0]":       {exact(role("aws_iam_role.counted[0]"), github, `{`+stsAud+`, sub=like:"repo:acme/counted:*"}`, NoChangeListed, UnreadResource)},
		"module.ci.aws_iam_role.runner": {exact(role("module.ci.aws_iam_role.runner"), github, `{`+stsAud+`, sub="repo:acme/infra:environment:build"}`, NoChangeListed, UnreadResource)},
	},
}

// TestExpectations judges every rendered case against the table: the
// grants of each address, in order, with their target, issuer, admitted
// set, exactness and anomaly kinds.
func TestExpectations(t *testing.T) {
	examined := 0
	for _, d := range documents(t) {
		if _, no := refused[d.name]; no {
			continue
		}
		table, ok := expectations[d.name]
		if !ok {
			t.Errorf("%s has no expectations; it would be judged by the rendering alone", d.name)
			continue
		}
		gs, err := grantsOf(t, d)
		if err != nil {
			t.Errorf("%s: %v", d.name, err)
			continue
		}
		by, order := grantsByAddress(t, gs)
		for _, address := range order {
			if _, named := table[address]; !named {
				t.Errorf("%s: %s yields %d grants the table does not name", d.name, address, len(by[address]))
			}
		}
		for _, address := range slices.Sorted(maps.Keys(table)) {
			wants, got := table[address], by[address]
			if len(got) != len(wants) {
				t.Errorf("%s: %s yields %d grants, want %d", d.name, address, len(got), len(wants))
				continue
			}
			for i, w := range wants {
				examined++
				g := got[i]
				where := d.name + ": " + address + " grant " + itoa(i)
				if g.Target != w.target {
					t.Errorf("%s: target %+v, want %+v", where, g.Target, w.target)
				}
				if g.Issuer != w.issuer {
					t.Errorf("%s: issuer %q, want %q", where, g.Issuer, w.issuer)
				}
				if s := g.Admits.String(); s != w.admits {
					t.Errorf("%s: admits %s\n  want %s", where, s, w.admits)
				}
				if g.Exact() != w.exact {
					t.Errorf("%s: exact %v, want %v; caveats %v", where, g.Exact(), w.exact, g.Admits.Caveats())
				}
				if g.Effect != trust.Allow {
					t.Errorf("%s: effect %q", where, g.Effect)
				}
				var kinds []string
				for _, a := range g.Anomalies {
					kinds = append(kinds, a.Kind)
				}
				if !slices.Equal(kinds, w.kinds) {
					t.Errorf("%s: anomaly kinds %v\n  want %v", where, kinds, w.kinds)
				}
			}
		}
	}
	if examined == 0 {
		t.Fatalf("examined no grants")
	}
	t.Logf("examined %d grants", examined)
}

// TestResourcesExamined: a reader says which instances it examined and
// which trust-shaped ones it could not read, so that a caller never prints
// "no trust" over a document that holds resources it did not read, and
// "zero resources examined" over an empty one.
func TestResourcesExamined(t *testing.T) {
	plan, err := ParsePlan(caseDocument(t, "01-aws-plan").raw, "plan.json")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(plan.Resources) != 21 {
		t.Errorf("%d resources examined, want 21 role instances", len(plan.Resources))
	}
	for _, r := range plan.Resources {
		if r.Type != "aws_iam_role" || !slices.Equal(r.Actions, []string{"create"}) {
			t.Errorf("resource %+v is not a created role", r)
		}
	}
	if len(plan.Unread) != 0 || plan.FormatVersion != "1.2" || plan.TerraformVersion != "1.15.5" || plan.Source != "plan.json" {
		t.Errorf("plan %+v", plan)
	}
	if plan.Complete == nil || !*plan.Complete || plan.Errored == nil || *plan.Errored {
		t.Errorf("complete %v errored %v; the recorded plan states both", plan.Complete, plan.Errored)
	}

	state, err := ParseState(caseDocument(t, "04-aws-state").raw, "state.json")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(state.Resources) != 10 {
		t.Errorf("%d resources examined, want 10", len(state.Resources))
	}
	if len(state.Unread) != 1 || state.Unread[0].Address != "awscc_iam_role.cc" || state.Unread[0].Type != "awscc_iam_role" || state.Unread[0].Actions != nil {
		t.Errorf("unread %+v, want the Cloud Control role", state.Unread)
	}
	if state.Resources[0].Actions != nil {
		t.Errorf("a state resource has no actions: %+v", state.Resources[0])
	}

	empty, err := ParseState(caseDocument(t, "09-empty-state").raw, "state.json")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(empty.Resources) != 0 || len(empty.Unread) != 0 || empty.TerraformVersion != "" || empty.FormatVersion != "1.0" {
		t.Errorf("empty state %+v", empty)
	}
	if gs := empty.Grants(clock, vocabulary); len(gs) != 0 {
		t.Errorf("an empty state states %d grants", len(gs))
	}

	actions, err := ParsePlan(caseDocument(t, "06-aws-plan-actions").raw, "plan.json")
	if err != nil {
		t.Fatalf("%v", err)
	}
	var seen []string
	for _, r := range actions.Resources {
		seen = append(seen, r.Address+" "+strings.Join(r.Actions, ",")+" "+r.Deposed)
	}
	// A change that both creates and forgets is one listed resource; a
	// resource the plan lists no change for is listed with no actions.
	wantSeen := []string{"aws_iam_role.kept no-op ", "aws_iam_role.old delete ", "aws_iam_role.old delete deadbeef", "aws_iam_role.replaced delete,create ", "aws_iam_role.rotated update ", "aws_iam_role.forgotten forget ", "aws_iam_role.reborn create,forget ", "aws_iam_role.hollow create ", "aws_iam_role.untargeted  "}
	if !slices.Equal(seen, wantSeen) {
		t.Errorf("resources %v\n  want %v", seen, wantSeen)
	}
	if actions.Complete == nil || *actions.Complete {
		t.Errorf("the targeted plan is not marked incomplete: %v", actions.Complete)
	}

	// A refresh-only plan lists no change at all; every resource is read
	// from its prior state, the module's included, and the unmapped type is
	// listed as unread.
	refreshOnly, err := ParsePlan(caseDocument(t, "14-refresh-only-plan").raw, "plan.json")
	if err != nil {
		t.Fatalf("%v", err)
	}
	seen = nil
	for _, r := range refreshOnly.Resources {
		seen = append(seen, r.Address+" "+strings.Join(r.Actions, ",")+" "+r.Deposed)
	}
	if !slices.Equal(seen, []string{"aws_iam_role.deploy  ", "aws_iam_role.marked  ", "aws_iam_role.counted[0]  ", "module.ci.aws_iam_role.runner  "}) || len(refreshOnly.Unread) != 1 || refreshOnly.Unread[0].Address != "awscc_iam_role.cc" {
		t.Errorf("refresh-only resources %v unread %+v", seen, refreshOnly.Unread)
	}
	if refreshOnly.Complete == nil || !*refreshOnly.Complete {
		t.Errorf("the refresh-only plan is complete: %v", refreshOnly.Complete)
	}
}

// TestRefusals: what is not a plan or a state document is refused with a
// sentence that says what it is, and never read.
func TestRefusals(t *testing.T) {
	plan := caseDocument(t, "01-aws-plan").raw
	state := caseDocument(t, "04-aws-state").raw
	tfstate := caseDocument(t, "08-raw-tfstate").raw
	cases := []struct {
		name  string
		raw   []byte
		parse string // "plan", "state" or "both"
		want  string
	}{
		{"empty", nil, "both", "empty input"},
		{"not json", []byte("{"), "both", "not a JSON document"},
		{"a list", []byte("[]"), "both", "the document is a list, not an object"},
		{"no version", []byte(`{"resource_changes": []}`), "both", "no format_version member"},
		{"version not a string", []byte(`{"format_version": 1.2, "resource_changes": []}`), "both", "format_version is not a string"},
		{"version not a number", []byte(`{"format_version": "one", "resource_changes": []}`), "both", `format_version "one" does not begin with a major version number`},
		{"major 2", []byte(`{"format_version": "2.0", "resource_changes": []}`), "both", `format_version "2.0" is major version 2; this reader understands major version 1`},
		{"major 0", []byte(`{"format_version": "0.1", "resource_changes": []}`), "both", `format_version "0.1" is major version 0`},
		{"raw state by lineage", []byte(`{"version": 4, "lineage": "x", "resources": []}`), "both", "this is a raw state file; run terraform show -json and pass its output"},
		{"raw state by serial", []byte(`{"format_version": "1.0", "serial": 3}`), "both", "this is a raw state file"},
		{"raw state by shape", []byte(`{"version": 4, "resources": [{"instances": []}]}`), "both", "this is a raw state file"},
		{"recorded raw state", tfstate, "both", "this is a raw state file"},
		{"a state handed to ParsePlan", state, "plan", "this is a state document (it has values and none of resource_changes, planned_values, configuration or prior_state); use ParseState"},
		{"an empty state handed to ParsePlan", []byte(`{"format_version": "1.0"}`), "plan", "this is not a plan document: none of resource_changes, planned_values, configuration or prior_state is present"},
		{"a plan handed to ParseState", plan, "state", "this is a plan document (it has resource_changes); use ParsePlan"},
		{"a plan without changes handed to ParseState", []byte(`{"format_version": "1.2", "planned_values": {}}`), "state", "this is a plan document (it has planned_values); use ParsePlan"},
		{"resource_changes not a list", []byte(`{"format_version": "1.2", "resource_changes": {}}`), "plan", "resource_changes is not a list"},
		{"a change that is not an object", []byte(`{"format_version": "1.2", "resource_changes": [1]}`), "plan", "resource_changes[0] is not an object"},
		{"a change with no address", []byte(`{"format_version": "1.2", "resource_changes": [{"type": "aws_iam_role"}]}`), "plan", "resource_changes[0] has no address"},
		{"a change with no change", []byte(`{"format_version": "1.2", "resource_changes": [{"address": "aws_iam_role.a", "type": "aws_iam_role"}]}`), "plan", "resource_changes[0] (aws_iam_role.a) has no change object"},
		{"values not an object", []byte(`{"format_version": "1.0", "values": []}`), "state", "values is not an object"},
		{"a module that is not an object", []byte(`{"format_version": "1.0", "values": {"root_module": {"child_modules": [1]}}}`), "state", "root_module.child_modules[0] is not an object"},
		{"a resource that is not an object", []byte(`{"format_version": "1.0", "values": {"root_module": {"resources": ["x"]}}}`), "state", "root_module.resources[0] is not an object"},
		{"a resource with no address", []byte(`{"format_version": "1.0", "values": {"root_module": {"resources": [{"type": "aws_iam_role"}]}}}`), "state", "root_module.resources[0] has no address"},
		{"a prior state that is not an object", []byte(`{"format_version": "1.2", "resource_changes": [], "prior_state": 1}`), "plan", "prior_state is not an object"},
		{"a configuration that is not an object", []byte(`{"format_version": "1.2", "resource_changes": [], "configuration": []}`), "plan", "configuration is not an object"},
		{"a module call that is not an object", []byte(`{"format_version": "1.2", "resource_changes": [], "configuration": {"root_module": {"module_calls": {"x": 1}}}}`), "plan", "configuration root_module.module_calls.x is not a module call object"},
		{"nested too deep", []byte(`{"format_version": "1.2", "resource_changes": [], "configuration": {"root_module": ` + strings.Repeat(`{"module_calls": {"x": {"module": `, 300) + `{}` + strings.Repeat(`}}}`, 300) + `}}`), "plan", "nested more than"},
		{"state nested too deep", []byte(`{"format_version": "1.0", "values": {"root_module": ` + strings.Repeat(`{"child_modules": [`, 300) + `{}` + strings.Repeat(`]}`, 300) + `}}`), "state", "nested more than"},
	}
	for _, c := range cases {
		if c.parse == "plan" || c.parse == "both" {
			if p, err := ParsePlan(c.raw, "input"); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("ParsePlan(%s): %v (%d resources), want an error containing %q", c.name, err, len(p.Resources), c.want)
			}
		}
		if c.parse == "state" || c.parse == "both" {
			if s, err := ParseState(c.raw, "input"); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("ParseState(%s): %v (%d resources), want an error containing %q", c.name, err, len(s.Resources), c.want)
			}
		}
	}
	if _, err := ParsePlan(plan, "plan.json"); err != nil {
		t.Errorf("the recorded plan is refused: %v", err)
	}
	if _, err := ParseState(state, "state.json"); err != nil {
		t.Errorf("the state is refused: %v", err)
	}
	// A refusal names the source the caller labelled, so that a CLI reading
	// several files can say which one.
	if _, err := ParsePlan([]byte(`{"format_version": "2.0"}`), "ci/plan.json"); err == nil || !strings.HasPrefix(err.Error(), "ci/plan.json: ") {
		t.Errorf("the refusal does not name the source: %v", err)
	}
}

// TestUnknownMembersIgnored: the format promises forward compatibility
// through unrecognised members, and the readers honour it at every level.
func TestUnknownMembersIgnored(t *testing.T) {
	raw := []byte(`{"format_version": "1.9", "terraform_version": "1.99.0", "future": {"x": 1}, "resource_changes": [
	  {"address": "aws_iam_role.a", "mode": "managed", "type": "aws_iam_role", "name": "a", "future": true,
	   "change": {"actions": ["create"], "before": null, "after": {"assume_role_policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Federated\":\"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com\"},\"Action\":\"sts:AssumeRoleWithWebIdentity\",\"Condition\":{\"StringEquals\":{\"token.actions.githubusercontent.com:sub\":\"repo:acme/infra:ref:refs/heads/main\"}}}]}", "future": 1}, "after_unknown": {"arn": true, "future": true}, "after_sensitive": {"future": []}, "future": null}}
	], "configuration": {"future": 1, "root_module": {"future": 2, "resources": [{"address": "aws_iam_role.a", "future": 3, "expressions": {"assume_role_policy": {"future": 4}}}]}}}`)
	p, err := ParsePlan(raw, "plan.json")
	if err != nil {
		t.Fatalf("%v", err)
	}
	gs := p.Grants(clock, vocabulary)
	if len(gs) != 1 || gs[0].Admits.String() != `{sub="repo:acme/infra:ref:refs/heads/main"}` || !gs[0].Exact() {
		t.Errorf("grants %s", render(gs))
	}
}

// TestDeterminism is the promise of docs/ENGINEERING.md section 2 at this
// layer: every document of the corpus read twice from fresh state renders
// the same grants byte for byte. The Makefile runs it twenty times in fresh
// processes, so a map iterated into output is caught across runs as well.
func TestDeterminism(t *testing.T) {
	examined := 0
	for _, d := range documents(t) {
		if _, no := refused[d.name]; no {
			continue
		}
		first, err := grantsOf(t, d)
		if err != nil {
			t.Fatalf("%s: %v", d.name, err)
		}
		again, _ := grantsOf(t, d)
		if a, b := render(first), render(again); !bytes.Equal(a, b) {
			t.Errorf("%s rendered differently on a second read:\n%s\n---\n%s", d.name, firstDifference(a, b), firstDifference(b, a))
		}
		examined++
	}
	if examined < 10 {
		t.Fatalf("examined %d documents; the corpus has more", examined)
	}
	t.Logf("examined %d documents twice each", examined)
}
