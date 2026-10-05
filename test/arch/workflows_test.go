package arch

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The rules a workflow is held to. Every violation names the one it breaks,
// so a fixture is held to the reason it is refused for, not merely to being
// refused: a rule that stopped working would leave its fixture accepted.
const (
	// The top of the workflow is not exactly one permissions: {}, so its
	// jobs would start from a grant instead of from nothing.
	ruleTopPermissions = "top-permissions"
	// write-all or read-all, at the top or in a job: every scope at once,
	// id-token among them.
	ruleBroadGrant = "broad-grant"
	// A job holds a grant other than the one jobGrants names for it, or a
	// job jobGrants names is not in the workflow.
	ruleJobGrant = "job-grant"
	// id-token: write in a workflow that an event outside idTokenEvents can
	// start, where code or text from outside the repository can reach a job
	// that can ask for a signing identity.
	ruleIDTokenTrigger = "id-token-trigger"
	// A uses: that is not owner/repository[/path]@<40 hexadecimal digits>:
	// a tag or a branch can be moved to other code after it was read, and a
	// shortened SHA can be matched by another commit.
	rulePin = "pin"
	// A checkout that does not set persist-credentials: false in its with:,
	// which leaves the token in .git/config for every later step to read.
	rulePersistCredentials = "persist-credentials"
	// A permissions:, on: or step written in a form this reader does not
	// follow: a flow mapping, an anchor, an alias, a tag, a merge key, a key
	// in double quotes holding an escape, or a line break other than a line
	// feed. The check cannot tell what such a workflow grants, so it refuses
	// it.
	ruleUnreadable = "unreadable"
	// A go-version other than go.mod's toolchain, or a setup-go step that
	// names none (toolchain_test.go).
	ruleGoVersion = "go-version"
)

// jobGrants names, for each workflow and job, the only permissions that job
// may hold. Every job not named here holds none: its permissions are absent,
// {} or only none. A job named here must exist and hold exactly this set, so
// an entry cannot outlive the job it was written for.
//
// release.yml's build job asks GitHub for a signing identity (id-token) to
// attest the files it built (attestations). No workflow here writes the
// repository's contents, packages or releases.
var jobGrants = map[string]map[string]map[string]string{
	"release.yml": {
		"build": {"id-token": "write", "attestations": "write"},
	},
}

// idTokenEvents are the only events that may start a workflow that grants
// id-token: write: a push, which needs write access to the repository, and a
// run started by hand by someone who has it. Every other event (a pull
// request, a comment, another workflow's run) can carry what an outsider
// wrote into the job.
var idTokenEvents = map[string]bool{"push": true, "workflow_dispatch": true}

// violation is one rule a workflow breaks, at a line (0 for the workflow as
// a whole).
type violation struct {
	line   int
	rule   string
	detail string
}

func (v violation) String() string {
	return fmt.Sprintf("%d: %s: %s", v.line, v.rule, v.detail)
}

// examined counts what checkWorkflow read, so a run that read nothing is
// seen as one.
type examined struct {
	events, jobs, grants, actions, checkouts int
}

// TestWorkflowsArePinnedAndHoldNoCredentials reads every workflow under
// .github/workflows and holds what a pull request could otherwise loosen
// without anyone reading the YAML closely:
//
//   - the workflow grants its token nothing at the top (permissions: {}), and
//     no job holds more than jobGrants names for it, never write-all or
//     read-all, so a compromised step has no access it was not given on
//     purpose;
//   - a workflow that can ask for a signing identity (id-token: write) starts
//     only from a push or by hand;
//   - every uses:, actions, reusable workflows and docker:// alike, is pinned
//     to a full commit SHA, because a tag can be moved to other code after it
//     was reviewed;
//   - every checkout sets persist-credentials: false, so the token is not
//     left in .git/config for the steps that follow to read;
//   - every workflow jobGrants names is there to be read.
func TestWorkflowsArePinnedAndHoldNoCredentials(t *testing.T) {
	paths := workflowPaths(t)
	var total examined
	seen := map[string]bool{}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(path)
		seen[name] = true
		read, found := checkWorkflow(name, string(raw))
		for _, v := range found {
			t.Errorf("%s:%s", name, v)
		}
		total.events += read.events
		total.jobs += read.jobs
		total.grants += read.grants
		total.actions += read.actions
		total.checkouts += read.checkouts
	}
	for _, name := range sortedKeys(jobGrants) {
		if !seen[name] {
			t.Errorf("%s: jobGrants names its jobs, and no workflow of that name is under .github/workflows", name)
		}
	}
	if total.events == 0 || total.jobs == 0 || total.actions == 0 || total.checkouts == 0 {
		t.Fatalf("%d events, %d jobs, %d actions and %d checkouts in %d workflows; this test examined too little",
			total.events, total.jobs, total.actions, total.checkouts, len(paths))
	}
	t.Logf("read %d workflows: %d events, %d jobs, %d job grants, %d actions and %d checkouts",
		len(paths), total.events, total.jobs, total.grants, total.actions, total.checkouts)
}

// workflowFixtures is every file under testdata/workflows: the name each is
// read as (jobGrants keys on it), and the one rule it breaks, "" for a
// control that breaks none. Each fixture passes every check but one, so
// each rule is shown refusing on its own; those read as release.yml each
// change one thing in release-shape.yml.
var workflowFixtures = []struct{ file, as, rule string }{
	{"release-shape.yml", "release.yml", ""},
	{"tag-pin.yml", "tag-pin.yml", rulePin},
	{"short-sha.yml", "short-sha.yml", rulePin},
	{"reusable-workflow-by-tag.yml", "reusable-workflow-by-tag.yml", rulePin},
	{"docker-action.yml", "docker-action.yml", rulePin},
	{"action-after-a-block-scalar-name.yml", "action-after-a-block-scalar-name.yml", rulePin},
	{"top-write-all.yml", "top-write-all.yml", ruleBroadGrant},
	{"top-read-all.yml", "top-read-all.yml", ruleBroadGrant},
	{"job-write-all.yml", "job-write-all.yml", ruleBroadGrant},
	{"job-read-all.yml", "job-read-all.yml", ruleBroadGrant},
	{"build-job-writes-contents.yml", "release.yml", ruleJobGrant},
	{"id-token-on-pull-request-target.yml", "release.yml", ruleIDTokenTrigger},
	{"id-token-on-issue-comment.yml", "release.yml", ruleIDTokenTrigger},
	{"checkout-keeps-credentials.yml", "checkout-keeps-credentials.yml", rulePersistCredentials},
	{"checkout-persist-beside-with.yml", "checkout-persist-beside-with.yml", rulePersistCredentials},
	{"job-grant-in-flow-style.yml", "job-grant-in-flow-style.yml", ruleUnreadable},
	{"job-grant-by-alias.yml", "release.yml", ruleUnreadable},
	{"triggers-in-flow-style.yml", "release.yml", ruleUnreadable},
	{"job-grant-under-an-escaped-key.yml", "job-grant-under-an-escaped-key.yml", ruleUnreadable},
	{"job-grant-under-an-anchored-key.yml", "job-grant-under-an-anchored-key.yml", ruleUnreadable},
	{"job-grant-under-a-tagged-key.yml", "job-grant-under-a-tagged-key.yml", ruleUnreadable},
	{"short-go-version.yml", "release.yml", ruleGoVersion},
	{"setup-go-from-file.yml", "release.yml", ruleGoVersion},
	{"setup-go-after-a-block-scalar-name.yml", "setup-go-after-a-block-scalar-name.yml", ruleGoVersion},
}

// fixtureToolchain is the Go every fixture's setup-go means to install. It
// is fixed here, not read from go.mod, so a toolchain upgrade changes no
// fixture.
const fixtureToolchain = "1.27.1"

// TestEachWorkflowFixtureIsRefusedForItsOwnReason holds the two checks to
// the fixtures: each fixture breaks exactly the rule it is named for and no
// other, across the workflow check and the toolchain check together, and
// each control breaks none. Today's ci.yml is held as a control beside them.
func TestEachWorkflowFixtureIsRefusedForItsOwnReason(t *testing.T) {
	dir := filepath.Join("testdata", "workflows")
	files, err := filepath.Glob(filepath.Join(dir, "*"))
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, f := range workflowFixtures {
		listed[f.file] = true
	}
	for _, f := range files {
		if !listed[filepath.Base(f)] {
			t.Errorf("%s is under %s and not in workflowFixtures, so nothing holds it to a reason", filepath.Base(f), dir)
		}
	}

	refused := map[string]int{}
	controls := 0
	for _, f := range workflowFixtures {
		raw, err := os.ReadFile(filepath.Join(dir, f.file))
		if err != nil {
			t.Errorf("%s: %v", f.file, err)
			continue
		}
		_, lint := checkWorkflow(f.as, string(raw))
		_, _, tool := checkGoVersions(string(raw), fixtureToolchain)
		found := append(lint, tool...)
		if got := rulesOf(found); got != f.rule {
			t.Errorf("%s, read as %s: broke %q; want %q\n%s", f.file, f.as, got, f.rule, listViolations(found))
			continue
		}
		if f.rule == "" {
			controls++
		} else {
			refused[f.rule]++
		}
	}
	// A missing or doubled top-level permissions line is shown by
	// TestTheTopGrantIsExactlyNothing; every other rule by a fixture here.
	for _, rule := range []string{ruleBroadGrant, ruleJobGrant, ruleIDTokenTrigger, rulePin,
		rulePersistCredentials, ruleUnreadable, ruleGoVersion} {
		if refused[rule] == 0 {
			t.Errorf("no fixture is refused for %s alone, so nothing shows that rule refusing", rule)
		}
	}

	ci, err := os.ReadFile(filepath.Join(moduleRoot(t), ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	_, lint := checkWorkflow("ci.yml", string(ci))
	_, _, tool := checkGoVersions(string(ci), toolchainOf(t))
	if found := append(lint, tool...); len(found) != 0 {
		t.Errorf("ci.yml, the control, broke %q\n%s", rulesOf(found), listViolations(found))
	}
	t.Logf("%d fixtures (%d controls) and ci.yml; refused for each rule: %v", len(workflowFixtures), controls, refused)
}

// TestTheTopGrantIsExactlyNothing: a workflow whose top holds no
// permissions line, or two, or a grant of its own, starts its jobs from the
// repository's default grant, from whichever line GitHub reads, or from that
// grant; each is refused.
func TestTheTopGrantIsExactlyNothing(t *testing.T) {
	const clean = `name: top
on: push
permissions: {}
jobs:
  check:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
`
	if _, found := checkWorkflow("top.yml", clean); len(found) != 0 {
		t.Fatalf("the starting workflow is not clean, so it shows nothing:\n%s", listViolations(found))
	}
	cases := map[string]string{
		"no permissions line":   strings.Replace(clean, "permissions: {}\n", "", 1),
		"two permissions lines": strings.Replace(clean, "permissions: {}\n", "permissions: {}\npermissions: {}\n", 1),
		"a grant at the top":    strings.Replace(clean, "permissions: {}\n", "permissions:\n  contents: read\n", 1),
	}
	for name, text := range cases {
		if text == clean {
			t.Fatalf("%s: the replacement changed nothing", name)
		}
		_, found := checkWorkflow("top.yml", text)
		if got := rulesOf(found); got != ruleTopPermissions {
			t.Errorf("%s: broke %q; want %q\n%s", name, got, ruleTopPermissions, listViolations(found))
		}
	}
}

// TestALineBreakOrKeyThisReaderDoesNotFollowIsRefused: YAML ends a line at
// a carriage return that no line feed follows, and YAML 1.1, which parsers
// still read, at U+0085, U+2028 and U+2029 too; this reader splits only on
// a line feed, so what follows any of them on its line would be read as
// the rest of that line's value. An alias standing for a key names a key
// this reader cannot see. Each, put into a workflow that is otherwise
// clean, is refused as unreadable, by the workflow check and, for a line
// break, by the toolchain check as well, which reads the lines the same
// way. So is a step's uses key written with an escape, which YAML reads as
// uses and keyOf does not decode.
func TestALineBreakOrKeyThisReaderDoesNotFollowIsRefused(t *testing.T) {
	const clean = `name: check
on: pull_request_target
permissions: {}
jobs:
  check:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with:
          go-version: '1.27.1'
`
	if _, found := checkWorkflow("check.yml", clean); len(found) != 0 {
		t.Fatalf("the starting workflow is not clean, so it shows nothing:\n%s", listViolations(found))
	}
	if _, _, found := checkGoVersions(clean, fixtureToolchain); len(found) != 0 {
		t.Fatalf("the starting workflow installs another Go, so it shows nothing:\n%s", listViolations(found))
	}
	const hidden = "    permissions: write-all\n"
	breaks := map[string]string{
		"a carriage return": "\r",
		"U+0085":            "\u0085",
		"U+2028":            " ",
		"U+2029":            " ",
	}
	for name, mark := range breaks {
		text := strings.Replace(clean, "ubuntu-24.04\n", "ubuntu-24.04"+mark+hidden, 1)
		if text == clean {
			t.Fatalf("%s: the replacement changed nothing", name)
		}
		_, lint := checkWorkflow("check.yml", text)
		if got := rulesOf(lint); got != ruleUnreadable {
			t.Errorf("%s, by the workflow check: broke %q; want %q\n%s", name, got, ruleUnreadable, listViolations(lint))
		}
		_, _, tool := checkGoVersions(text, fixtureToolchain)
		if got := rulesOf(tool); got != ruleUnreadable {
			t.Errorf("%s, by the toolchain check: broke %q; want %q\n%s", name, got, ruleUnreadable, listViolations(tool))
		}
	}
	// A carriage return before a line feed ends one line, as the line feed
	// alone does.
	if _, found := checkWorkflow("check.yml", strings.ReplaceAll(clean, "\n", "\r\n")); len(found) != 0 {
		t.Errorf("the workflow with each line ended by a carriage return and a line feed:\n%s", listViolations(found))
	}
	keys := map[string][2]string{
		"an alias for a key": {"    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    *grant : write-all\n"},
		"a step's uses key with an escape": {"      - uses: actions/setup-go@",
			"      - \"u\\x73es\": actions/checkout@v7\n      - uses: actions/setup-go@"},
	}
	for name, change := range keys {
		text := strings.Replace(clean, change[0], change[1], 1)
		if text == clean {
			t.Fatalf("%s: the replacement changed nothing", name)
		}
		if _, found := checkWorkflow("check.yml", text); rulesOf(found) != ruleUnreadable {
			t.Errorf("%s: broke %q; want %q\n%s", name, rulesOf(found), ruleUnreadable, listViolations(found))
		}
	}
}

// TestCIChecksTheCollectorsModule: the collector is a module of its own, so
// make build, vet and test at the root never reach it. ci.yml runs it
// through make collect, or through make check, which runs make collect.
func TestCIChecksTheCollectorsModule(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(moduleRoot(t), ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	lines, unread := structure(string(raw))
	if len(unread) != 0 {
		t.Fatalf("ci.yml is not read as YAML reads it:\n%s", listViolations(unread))
	}
	runs := 0
	for _, l := range lines {
		k, v, ok := keyOf(l.text)
		if !ok || k != "run" {
			continue
		}
		runs++
		if v == "make collect" || v == "make check" {
			t.Logf("ci.yml:%d runs %s, the run step %d read", l.n, v, runs)
			return
		}
	}
	if runs == 0 {
		t.Fatal("ci.yml has no run: step; this test examined nothing")
	}
	t.Errorf("none of ci.yml's %d run steps is make collect or make check, so the collector's module is never built or tested there", runs)
}

// checkWorkflow reads one workflow and returns what it read and every rule
// it breaks. It reads YAML line by line, by indentation, as workflows are
// written; whatever it does not follow is a violation of its own
// (ruleUnreadable), refused and never accepted.
func checkWorkflow(name, text string) (read examined, found []violation) {
	lines, unread := structure(text)
	found = append(found, unread...)
	add := func(line int, rule, format string, args ...any) {
		found = append(found, violation{line, rule, fmt.Sprintf(format, args...)})
	}
	for _, l := range lines {
		if opaque(l.text) {
			add(l.n, ruleUnreadable, "%q holds a flow mapping, an anchor, an alias, a tag, a merge key or an escape in a key, which this check does not follow", l.text)
		} else if k, _, ok := keyOf(l.text); ok && k == "uses" && usesLine.FindStringSubmatch(l.text) == nil {
			add(l.n, ruleUnreadable, "%q names an action in a form this check does not read", l.text)
		}
	}

	var perms, ons, jobsAt []int
	for i, l := range lines {
		if l.indent != 0 {
			continue
		}
		k, _, ok := keyOf(l.text)
		if !ok {
			continue
		}
		switch k {
		case "permissions":
			perms = append(perms, i)
		case "on":
			ons = append(ons, i)
		case "jobs":
			jobsAt = append(jobsAt, i)
		}
	}

	// The top: exactly one permissions: {}.
	if len(perms) != 1 {
		add(0, ruleTopPermissions, "%d top-level permissions lines; want exactly one, permissions: {}", len(perms))
	} else {
		l := lines[perms[0]]
		_, v, _ := keyOf(l.text)
		switch v {
		case "{}":
		case "write-all", "read-all":
			add(l.n, ruleBroadGrant, "the top grants %s; want permissions: {}", v)
		default:
			add(l.n, ruleTopPermissions, "the top grants %q; want permissions: {}", v)
		}
	}

	// The events that start it.
	events, eventsRead := triggers(lines, ons, add)
	read.events = len(events)

	// The jobs, and what each holds.
	idToken := 0 // the line of a job's grant of id-token: write, if any
	present := map[string]bool{}
	if len(jobsAt) > 1 {
		add(lines[jobsAt[1]].n, ruleUnreadable, "a second top-level jobs:")
	}
	if len(jobsAt) >= 1 {
		at := jobsAt[0]
		if _, v, _ := keyOf(lines[at].text); v != "" {
			add(lines[at].n, ruleUnreadable, "jobs: %q is not a block of jobs", v)
		}
		body := blockAfter(lines, at)
		for _, j := range childrenOf(body, add) {
			id, v, ok := keyOf(body[j].text)
			if !ok || strings.HasPrefix(body[j].text, "- ") {
				add(body[j].n, ruleUnreadable, "%q is not a job", body[j].text)
				continue
			}
			read.jobs++
			present[id] = true
			if v != "" {
				add(body[j].n, ruleUnreadable, "job %s: %q is not a block", id, v)
				continue
			}
			grant, grantAt, ok := jobGrant(blockAfter(body, j), id, add, &read)
			if !ok {
				continue
			}
			if grant["id-token"] == "write" {
				idToken = grantAt
			}
			want := jobGrants[name][id]
			if !sameGrant(grant, want) {
				line := grantAt
				if line == 0 {
					line = body[j].n
				}
				add(line, ruleJobGrant, "job %s holds %s; want %s", id, grantString(grant), grantString(want))
			}
		}
	}
	for _, id := range sortedKeys(jobGrants[name]) {
		if !present[id] {
			add(0, ruleJobGrant, "jobGrants names job %s, which this workflow does not have", id)
		}
	}

	// A signing identity only for a push or a run started by hand.
	if idToken != 0 && eventsRead {
		var outside []string
		for _, e := range events {
			if !idTokenEvents[e] {
				outside = append(outside, e)
			}
		}
		if len(outside) > 0 {
			add(idToken, ruleIDTokenTrigger, "id-token: write in a workflow that %s can start; only push and workflow_dispatch may", strings.Join(outside, ", "))
		}
	}

	// Every uses: pinned; every checkout without the token left behind.
	for i, l := range lines {
		m := usesLine.FindStringSubmatch(l.text)
		if m == nil {
			continue
		}
		read.actions++
		ref := unquote(m[1])
		if !pinned.MatchString(ref) {
			add(l.n, rulePin, "%s is not pinned to a full commit SHA", ref)
		}
		if !strings.HasPrefix(ref, "actions/checkout@") {
			continue
		}
		read.checkouts++
		if !withSets(lines, i, persistOff) {
			add(l.n, rulePersistCredentials, "this checkout does not set persist-credentials: false in its with:")
		}
	}
	return read, dedupe(found)
}

// triggers reads the workflow's on: as a list of event names: one name, a
// flow list of names, a block of names, or a block sequence of them. Any
// other form is a violation, and read is false.
func triggers(lines []yamlLine, ons []int, add func(int, string, string, ...any)) (events []string, read bool) {
	if len(ons) != 1 {
		add(0, ruleUnreadable, "%d top-level on: lines; want exactly one", len(ons))
		return nil, false
	}
	l := lines[ons[0]]
	_, v, _ := keyOf(l.text)
	if v != "" {
		if eventName.MatchString(v) {
			return []string{v}, true
		}
		if m := flowList.FindStringSubmatch(v); m != nil {
			for _, item := range strings.Split(m[1], ",") {
				item = unquote(strings.TrimSpace(item))
				if !eventName.MatchString(item) {
					add(l.n, ruleUnreadable, "on: %q is not a list of event names", v)
					return nil, false
				}
				events = append(events, item)
			}
			return events, true
		}
		add(l.n, ruleUnreadable, "on: %q is not an event, a list of events or a block", v)
		return nil, false
	}
	body := blockAfter(lines, ons[0])
	if len(body) == 0 {
		add(l.n, ruleUnreadable, "on: names no event")
		return nil, false
	}
	read = true
	for _, i := range childrenOf(body, add) {
		text := body[i].text
		if item, ok := strings.CutPrefix(text, "- "); ok {
			text = unquote(strings.TrimSpace(item))
		} else if k, _, ok := keyOf(text); ok {
			text = k
		}
		if !eventName.MatchString(text) {
			add(body[i].n, ruleUnreadable, "%q under on: is not an event", body[i].text)
			read = false
			continue
		}
		events = append(events, text)
	}
	return events, read
}

// jobGrant reads a job's permissions (absent, {}, or a block of scope:
// level lines) as the set of scopes it grants; none grants nothing.
// write-all and read-all are violations of their own, and any other form is
// unreadable. at is the line of the permissions key, 0 when there is none;
// ok is false when the grant could not be read as a set.
func jobGrant(job []yamlLine, id string, add func(int, string, string, ...any), read *examined) (grant map[string]string, at int, ok bool) {
	grant = map[string]string{}
	var keys []int
	for _, i := range childrenOf(job, add) {
		if k, _, isKey := keyOf(job[i].text); isKey && k == "permissions" && !strings.HasPrefix(job[i].text, "- ") {
			keys = append(keys, i)
		}
	}
	switch len(keys) {
	case 0:
		return grant, 0, true
	case 1:
	default:
		add(job[keys[1]].n, ruleUnreadable, "job %s: a second permissions:", id)
		return nil, 0, false
	}
	read.grants++
	l := job[keys[0]]
	_, v, _ := keyOf(l.text)
	switch v {
	case "{}":
		return grant, l.n, true
	case "write-all", "read-all":
		add(l.n, ruleBroadGrant, "job %s grants %s", id, v)
		return nil, 0, false
	case "":
	default:
		add(l.n, ruleUnreadable, "job %s: permissions: %q is not a block of scopes", id, v)
		return nil, 0, false
	}
	scopes := blockAfter(job, keys[0])
	if len(scopes) == 0 {
		add(l.n, ruleUnreadable, "job %s: permissions: with nothing under it", id)
		return nil, 0, false
	}
	ok = true
	for _, s := range scopes {
		m := scopeLine.FindStringSubmatch(s.text)
		if s.indent != scopes[0].indent || m == nil {
			add(s.n, ruleUnreadable, "job %s: %q is not a scope: read, write or none", id, s.text)
			ok = false
			continue
		}
		scope, level := m[1], unquote(m[2])
		if _, twice := grant[scope]; twice {
			add(s.n, ruleUnreadable, "job %s: %s is granted twice", id, scope)
			ok = false
			continue
		}
		if level != "read" && level != "write" && level != "none" {
			add(s.n, ruleUnreadable, "job %s: %s: %q is not read, write or none", id, scope, level)
			ok = false
			continue
		}
		grant[scope] = level
	}
	for scope, level := range grant {
		if level == "none" {
			delete(grant, scope)
		}
	}
	return grant, l.n, ok
}

var (
	usesLine   = regexp.MustCompile(`^(?:-\s+)?uses:\s*(\S+)$`)
	pinned     = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$`)
	persistOff = regexp.MustCompile(`^persist-credentials:\s*false$`)
	keyValue   = regexp.MustCompile(`^(?:-\s+)?([A-Za-z0-9_.-]+|"[^"]*"|'[^']*'|<<)\s*:(?:\s+(.*))?$`)
	scopeLine  = regexp.MustCompile(`^([a-z-]+):\s+(\S+)$`)
	eventName  = regexp.MustCompile(`^[a-z_]+$`)
	flowList   = regexp.MustCompile(`^\[([^\[\]{}]*)\]$`)
	blockMark  = regexp.MustCompile(`^[|>][-+0-9]*$`)
)

// yamlLine is one line of a workflow as the checks read it: its number from
// 1, its indentation in spaces, and its text without the indentation or a
// comment. Blank lines, comment lines and the lines of a block scalar (the
// script under run: |) are not structure and are not among them.
type yamlLine struct {
	n      int
	indent int
	text   string
}

// structure reads text's lines as yamlLines. YAML also ends a line at a
// carriage return that no line feed follows, and YAML 1.1, which parsers
// still read, at U+0085, U+2028 and U+2029; this reader splits on the line
// feed alone, and would read what follows any of the others as the rest of
// the line before it. Each line holding one is returned in unread, a
// violation of its own, wherever it stands, in a comment or a block scalar
// as much as in a key's line.
func structure(text string) (out []yamlLine, unread []violation) {
	raw := strings.Split(text, "\n")
	for i, line := range raw {
		if strings.ContainsAny(strings.TrimSuffix(line, "\r"), "\r\u0085\u2028\u2029") {
			unread = append(unread, violation{i + 1, ruleUnreadable,
				"a carriage return before no line feed, or U+0085, U+2028 or U+2029: YAML ends a line there, and this check does not"})
		}
	}
	for i := 0; i < len(raw); i++ {
		line := strings.TrimRight(raw[i], " \t\r")
		body := strings.TrimLeft(line, " ")
		if body == "" || strings.HasPrefix(body, "#") {
			continue
		}
		indent := len(line) - len(body)
		body = withoutComment(body)
		out = append(out, yamlLine{n: i + 1, indent: indent, text: body})
		if !blockMark.MatchString(valueOf(body)) {
			continue
		}
		// A block scalar's text is the lines below it indented past the
		// node it is the value of. For a key after a sequence entry's dash
		// that node is the entry's mapping, whose keys start after the
		// dash: a line at that column is the next key of the same entry,
		// not the scalar's text.
		parent := indent
		if _, _, ok := keyOf(body); ok && strings.HasPrefix(body, "-") {
			parent = afterDash(indent, body)
		}
		for i+1 < len(raw) {
			next := strings.TrimRight(raw[i+1], " \t\r")
			rest := strings.TrimLeft(next, " ")
			if rest != "" && len(next)-len(rest) <= parent {
				break
			}
			i++
		}
	}
	return out, unread
}

// withoutComment cuts a comment off a line: a # after a space or a tab,
// outside a quoted scalar.
func withoutComment(body string) string {
	var quote byte
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case quote == '\'':
			if c == '\'' && i+1 < len(body) && body[i+1] == '\'' {
				i++
			} else if c == '\'' {
				quote = 0
			}
		case quote == '"':
			if c == '\\' {
				i++
			} else if c == '"' {
				quote = 0
			}
		case (c == '\'' || c == '"') && startsScalar(body[:i]):
			quote = c
		case c == '#' && i > 0 && (body[i-1] == ' ' || body[i-1] == '\t'):
			return strings.TrimRight(body[:i], " \t")
		}
	}
	return body
}

// startsScalar reports whether a quote after before opens a quoted scalar:
// at the start of the line, after a key's colon, a sequence's dash, or the
// opening or a comma of a flow collection.
func startsScalar(before string) bool {
	before = strings.TrimRight(before, " \t")
	return before == "" || strings.HasSuffix(before, ":") || strings.HasSuffix(before, "-") ||
		strings.HasSuffix(before, "[") || strings.HasSuffix(before, "{") || strings.HasSuffix(before, ",")
}

// keyOf splits a key: value line, a sequence entry's included, into its key
// (unquoted) and its value.
func keyOf(text string) (key, value string, ok bool) {
	m := keyValue.FindStringSubmatch(text)
	if m == nil {
		return "", "", false
	}
	return unquote(m[1]), m[2], true
}

// valueOf is a line's value: what follows a key's colon, or a sequence
// entry that is not a key.
func valueOf(text string) string {
	if _, v, ok := keyOf(text); ok {
		return v
	}
	if item, ok := strings.CutPrefix(text, "- "); ok {
		return strings.TrimSpace(item)
	}
	return ""
}

// opaque reports a line whose node this reader cannot follow: a merge key,
// a complex key, a key in double quotes holding an escape, which keyOf does
// not decode, a line that starts with an anchor, an alias or a tag, which
// keyOf reads no key in whatever key follows, a flow mapping other than {},
// a flow list holding a mapping or left open, or a value that is an anchor,
// an alias or a tag.
func opaque(text string) bool {
	if strings.HasPrefix(text, "&") || strings.HasPrefix(text, "*") || strings.HasPrefix(text, "!") {
		return true
	}
	if m := keyValue.FindStringSubmatch(text); m != nil && m[1][0] == '"' && strings.Contains(m[1], `\`) {
		return true
	}
	if k, _, ok := keyOf(text); ok && k == "<<" {
		return true
	}
	if strings.HasPrefix(text, "? ") {
		return true
	}
	v := valueOf(text)
	switch {
	case v == "" || v == "{}":
		return false
	case v[0] == '{', v[0] == '&', v[0] == '*', v[0] == '!':
		return true
	case v[0] == '[':
		return strings.Contains(v, "{") || !strings.HasSuffix(v, "]")
	}
	return false
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// blockAfter is the lines under lines[i]: those after it indented more than
// it, up to the first that is not.
func blockAfter(lines []yamlLine, i int) []yamlLine {
	j := i + 1
	for j < len(lines) && lines[j].indent > lines[i].indent {
		j++
	}
	return lines[i+1 : j]
}

// childrenOf is the indices of a block's direct children: the lines at the
// block's first indentation. A line indented less than that is malformed
// YAML, and a violation.
func childrenOf(block []yamlLine, add func(int, string, string, ...any)) []int {
	if len(block) == 0 {
		return nil
	}
	var out []int
	for i, l := range block {
		switch {
		case l.indent == block[0].indent:
			out = append(out, i)
		case l.indent < block[0].indent:
			add(l.n, ruleUnreadable, "%q is indented less than the lines before it", l.text)
		}
	}
	return out
}

// withSets reports whether the step that holds lines[i] has a line matching
// want directly under its with:. The step is the "- " line at lines[i], or
// else the nearest line above indented less than lines[i], when that line
// is a "- " line; it runs while the lines below it are indented more.
func withSets(lines []yamlLine, i int, want *regexp.Regexp) bool {
	start := -1
	if strings.HasPrefix(lines[i].text, "- ") {
		start = i
	} else {
		for j := i - 1; j >= 0; j-- {
			if lines[j].indent < lines[i].indent {
				if strings.HasPrefix(lines[j].text, "- ") {
					start = j
				}
				break
			}
		}
	}
	if start < 0 {
		return false
	}
	// The step's keys sit where the text after its dash starts.
	keyIndent := afterDash(lines[start].indent, lines[start].text)
	body := blockAfter(lines, start)
	for j, l := range body {
		if l.indent != keyIndent {
			continue
		}
		if k, v, ok := keyOf(l.text); !ok || k != "with" || v != "" {
			continue
		}
		with := blockAfter(body, j)
		for _, w := range with {
			if w.indent == with[0].indent && want.MatchString(w.text) {
				return true
			}
		}
	}
	return false
}

// afterDash is the column where the text after a sequence entry's dash
// starts, for an entry whose dash is at indent: the column of the entry's
// first key.
func afterDash(indent int, text string) int {
	return indent + len(text) - len(strings.TrimLeft(text[1:], " "))
}

func sameGrant(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for scope, level := range want {
		if got[scope] != level {
			return false
		}
	}
	return true
}

func grantString(grant map[string]string) string {
	if len(grant) == 0 {
		return "nothing"
	}
	var parts []string
	for _, scope := range sortedKeys(grant) {
		parts = append(parts, scope+": "+grant[scope])
	}
	return strings.Join(parts, ", ")
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// dedupe keeps one violation of each rule at each line: a line both opaque
// and an unreadable grant is one reason, said once.
func dedupe(found []violation) []violation {
	type key struct {
		line int
		rule string
	}
	seen := map[key]bool{}
	var out []violation
	for _, v := range found {
		k := key{v.line, v.rule}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, v)
	}
	return out
}

// rulesOf is the distinct rules broken, sorted and joined by commas: "" for
// none.
func rulesOf(found []violation) string {
	set := map[string]bool{}
	for _, v := range found {
		set[v.rule] = true
	}
	return strings.Join(sortedKeys(set), ",")
}

func listViolations(found []violation) string {
	var b strings.Builder
	for _, v := range found {
		fmt.Fprintf(&b, "    %s\n", v)
	}
	return b.String()
}

// moduleRoot is the engine module's root, from go env GOMOD.
func moduleRoot(t *testing.T) string {
	t.Helper()
	gomod, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil || strings.TrimSpace(string(gomod)) == "" {
		t.Fatalf("go env GOMOD: %q, %v", gomod, err)
	}
	return filepath.Dir(strings.TrimSpace(string(gomod)))
}

// workflowPaths is every workflow GitHub runs, .yml and .yaml alike.
func workflowPaths(t *testing.T) []string {
	t.Helper()
	dir := filepath.Join(moduleRoot(t), ".github", "workflows")
	var paths []string
	for _, pattern := range []string{"*.yml", "*.yaml"} {
		found, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, found...)
	}
	if len(paths) == 0 {
		t.Fatal("no workflow under .github/workflows; this test examined nothing")
	}
	sort.Strings(paths)
	return paths
}
