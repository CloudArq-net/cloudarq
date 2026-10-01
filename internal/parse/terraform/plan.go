package terraform

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// Resource is one instance of a resource type the table names, as the
// document lists it: its absolute address, its type, the actions a plan
// takes on it, and the key of the deposed object when the change is to
// one rather than to the current object. Actions is nil in a state, and
// in a plan for an instance the plan lists no change for and the reader
// took from the prior state instead.
type Resource struct {
	Address string
	Type    string
	Actions []string
	Deposed string
}

// Listing is what a document lists that the reader takes note of, on
// both a Plan and a State. Resources are the instances the table names,
// in the order the document lists them; Unread are the instances whose
// type resembles a trust-bearing resource the table does not map, which
// Grants reports on every grant and which a caller must not read as
// absent. A caller prints the counts, so that an empty document reads as
// zero resources examined and never as no trust.
type Listing struct {
	Resources []Resource
	Unread    []Resource

	instances []instance
}

// examine files a listed resource and the objects the reader reads of
// it: under the table when its type is mapped, under the unread list when
// its type is trust-shaped, nowhere otherwise. A replace that forgets
// lists one resource and reads two objects of it.
func (l *Listing) examine(res Resource, objects ...instance) {
	if _, ok := lookup(res.Type); ok {
		l.Resources = append(l.Resources, res)
		l.instances = append(l.instances, objects...)
	} else if trustShaped(res.Type) {
		l.Unread = append(l.Unread, res)
	}
}

// Plan is terraform show -json output for a plan file, read as far as the
// Grants need. Complete and Errored are the plan's own flags, nil when
// the document predates them.
type Plan struct {
	Source           string
	FormatVersion    string
	TerraformVersion string
	Complete         *bool
	Errored          *bool
	Listing

	addresses []string // every instance the plan lists, table-named or not
	config    *configModule
	prior     map[string]instance // data documents rendered before apply, by absolute address
	deferred  map[string]bool     // data documents read only after apply, by absolute address
}

// State is terraform show -json output with no plan file: the values
// representation of the whole state, module tree included.
type State struct {
	Source           string
	FormatVersion    string
	TerraformVersion string
	Listing
}

// side is which value of a resource instance the reader read, which
// decides the origin sentence, the fact stamped on every grant, and what
// the evidence record says it read from: after, what the plan will send;
// before, of an object the plan deletes or forgets; the prior state, of
// an instance the plan lists no change for or a data document it
// rendered; or the state.
type side int

const (
	planned   side = iota // after
	deleted               // before, of a ["delete"] change
	forgotten             // before, of a change that includes "forget"
	held                  // prior_state: a resource no change is listed for, or a data document rendered before apply
	recorded              // a state's values
)

// from names the member of the plan a side was read from, for the
// evidence record; "" for a state, whose values have one place.
func (s side) from() string {
	switch s {
	case planned:
		return "after"
	case deleted, forgotten:
		return "before"
	case held:
		return "prior_state"
	}
	return ""
}

// instance is one resource object as the reader sees it, whichever
// document it came from: the attribute values Terraform wrote, the marks
// beside them, and enough of the listing to name it.
type instance struct {
	address string
	typ     string
	mode    string
	deposed string
	values  members
	unknown marks // nothing is marked in a state or a before value
	sensit  marks
	side    side
}

// ParsePlan reads terraform show -json output for a plan file. It returns
// an error only when the input is not a plan document at all: not one
// JSON object, a raw terraform.tfstate file, an unsupported major version,
// a state document, or one whose documented members have the wrong shape.
// Everything else is a Plan, and what cannot be understood in it becomes
// a Grant that admits everything with the reason attached. source is the
// caller's label for the document, which every refusal and every evidence
// record names.
func ParsePlan(raw []byte, source string) (Plan, error) {
	p, err := parsePlan(raw, source)
	if err != nil {
		return Plan{}, fmt.Errorf("%s: %w", source, err)
	}
	return p, nil
}

func parsePlan(raw []byte, source string) (Plan, error) {
	top, version, err := parseTop(raw)
	if err != nil {
		return Plan{}, err
	}
	if top.planMark() == "" {
		if _, ok := top["values"]; ok {
			return Plan{}, errors.New("this is a state document (it has values and none of resource_changes, planned_values, configuration or prior_state); use ParseState")
		}
		return Plan{}, errors.New("this is not a plan document: none of resource_changes, planned_values, configuration or prior_state is present")
	}
	p := Plan{Source: source, FormatVersion: version, Complete: top.flag("complete"), Errored: top.flag("errored"), prior: map[string]instance{}, deferred: map[string]bool{}}
	p.TerraformVersion, _ = top.text("terraform_version")
	changes, err := top.list("resource_changes", "resource_changes")
	if err != nil {
		return Plan{}, err
	}
	listed := map[string]bool{} // every address a change is listed for, deposed objects included
	for i, raw := range changes {
		c, err := parseChange(raw, i)
		if err != nil {
			return Plan{}, err
		}
		p.addresses = append(p.addresses, c.resource.Address)
		listed[c.resource.Address] = true
		if c.mode == "data" {
			// A data document read only after apply is listed here with its
			// values unknown; one read at plan time sits in prior_state.
			if slices.ContainsFunc(c.objects, func(inst instance) bool { return inst.unknown.marked("json") }) {
				p.deferred[c.resource.Address] = true
			}
			continue
		}
		p.examine(c.resource, c.objects...)
	}
	config, err := top.object("configuration", "configuration")
	if err != nil {
		return Plan{}, err
	}
	if config != nil {
		if p.config, err = parseConfiguration(config); err != nil {
			return Plan{}, err
		}
	}
	priorState, err := top.object("prior_state", "prior_state")
	if err != nil {
		return Plan{}, err
	}
	if priorState != nil {
		holds, err := parseValues(priorState, "prior_state ", true)
		if err != nil {
			return Plan{}, err
		}
		for _, inst := range holds {
			inst.side = held
			switch {
			case inst.mode == "data":
				if inst.typ == "aws_iam_policy_document" {
					p.prior[inst.address] = inst
				}
			case listed[inst.address]:
			default:
				// A resource the prior state holds and the plan lists no
				// change for is one a refresh-only or targeted plan leaves
				// as it is: Terraform writes a no-op change for every
				// resource it checked, so an unlisted one was excluded, not
				// checked, and it exists all the same.
				p.examine(Resource{Address: inst.address, Type: inst.typ}, inst)
			}
		}
	}
	return p, nil
}

// parseTop decodes the top level, refuses a raw state file and an
// unsupported format, and reads the version.
func parseTop(raw []byte) (members, string, error) {
	top, err := decodeObject(raw)
	if err != nil {
		return nil, "", err
	}
	if top.rawStateFile() {
		return nil, "", errors.New("this is a raw state file; run terraform show -json and pass its output")
	}
	version, err := top.formatVersion()
	if err != nil {
		return nil, "", err
	}
	return top, version, nil
}

// changeEntry is one element of resource_changes as the format documents
// it. The marks are decoded whole; the values only one level, as raw
// members, so that a policy string reaches the parser as written.
type changeEntry struct {
	Address string `json:"address"`
	Mode    string `json:"mode"`
	Type    string `json:"type"`
	Deposed string `json:"deposed"`
	Change  *struct {
		Actions         []string `json:"actions"`
		Before          members  `json:"before"`
		After           members  `json:"after"`
		AfterUnknown    any      `json:"after_unknown"`
		BeforeSensitive any      `json:"before_sensitive"`
		AfterSensitive  any      `json:"after_sensitive"`
	} `json:"change"`
}

// change is one resource change as the reader takes it: the listing, its
// mode, and the objects read of it, the one the plan will send first and
// the prior one after it.
type change struct {
	resource Resource
	mode     string
	objects  []instance
}

// parseChange reads one resource change. The after value is read unless
// the actions are exactly ["delete"] or ["forget"], for which it is unset;
// the before value is read for a delete, as the object the plan removes,
// and for any change that forgets, since Terraform "will discard its
// tracking information for the following objects, but it will not delete
// them": a forgotten object continues to exist, and so does its trust. A
// replace that forgets, ["create", "forget"] or ["forget", "create"],
// therefore reads both. The format page lists neither forget action; they
// are Terraform's own, from internal/command/jsonplan at v1.15.5 and at
// main, and the reader keys on the word rather than on the pair.
func parseChange(raw json.RawMessage, i int) (change, error) {
	where := "resource_changes[" + strconv.Itoa(i) + "]"
	if !isObject(raw) {
		return change{}, errors.New(where + " is not an object")
	}
	var c changeEntry
	if err := json.Unmarshal(raw, &c); err != nil {
		return change{}, fmt.Errorf("%s is not a change object: %v", where, err)
	}
	if c.Address == "" {
		return change{}, errors.New(where + " has no address")
	}
	if c.Change == nil {
		return change{}, fmt.Errorf("%s (%s) has no change object", where, c.Address)
	}
	actions := c.Change.Actions
	out := change{resource: Resource{Address: c.Address, Type: c.Type, Actions: slices.Clone(actions), Deposed: c.Deposed}, mode: c.Mode}
	object := instance{address: c.Address, typ: c.Type, deposed: c.Deposed}
	forgets := slices.Contains(actions, "forget")
	if !slices.Equal(actions, []string{"delete"}) && !slices.Equal(actions, []string{"forget"}) {
		object.values, object.unknown, object.sensit, object.side = c.Change.After, marks{c.Change.AfterUnknown}, marks{c.Change.AfterSensitive}, planned
		out.objects = append(out.objects, object)
	}
	if forgets || slices.Equal(actions, []string{"delete"}) {
		object.values, object.unknown, object.sensit, object.side = c.Change.Before, marks{}, marks{c.Change.BeforeSensitive}, deleted
		if forgets {
			object.side = forgotten
		}
		out.objects = append(out.objects, object)
	}
	return out, nil
}

// ParseState reads terraform show -json output for a state. It returns an
// error only when the input is not a state document at all: not one JSON
// object, a raw terraform.tfstate file, an unsupported major version, a
// plan document, or one whose documented members have the wrong shape.
// The empty state, {"format_version":"1.0"}, is a State with no
// resources, which is not the same as one with no trust.
func ParseState(raw []byte, source string) (State, error) {
	s, err := parseState(raw, source)
	if err != nil {
		return State{}, fmt.Errorf("%s: %w", source, err)
	}
	return s, nil
}

func parseState(raw []byte, source string) (State, error) {
	top, version, err := parseTop(raw)
	if err != nil {
		return State{}, err
	}
	if mark := top.planMark(); mark != "" {
		return State{}, fmt.Errorf("this is a plan document (it has %s); use ParsePlan", mark)
	}
	s := State{Source: source, FormatVersion: version}
	s.TerraformVersion, _ = top.text("terraform_version")
	instances, err := parseValues(top, "", false)
	if err != nil {
		return State{}, err
	}
	for _, inst := range instances {
		s.examine(Resource{Address: inst.address, Type: inst.typ}, inst)
	}
	return s, nil
}

// stateResource is one resource of a values representation.
type stateResource struct {
	Address         string  `json:"address"`
	Mode            string  `json:"mode"`
	Type            string  `json:"type"`
	Values          members `json:"values"`
	SensitiveValues any     `json:"sensitive_values"`
}

// stateModule is root_module or one of its child_modules: the resources
// and the modules beneath, each decoded only as far as its own shape.
type stateModule struct {
	Resources    []json.RawMessage `json:"resources"`
	ChildModules []json.RawMessage `json:"child_modules"`
}

// parseValues walks a values representation, root_module and every
// child_modules beneath it recursively, into the instances it lists in
// document order. where prefixes the sentences, "prior_state " for the
// values inside a plan; keepData keeps data resources, which only the
// prior state is read for.
func parseValues(top members, where string, keepData bool) ([]instance, error) {
	values, err := top.object("values", where+"values")
	if err != nil || values == nil {
		return nil, err
	}
	root, ok := values["root_module"]
	if !ok || isNull(root) {
		return nil, nil
	}
	var out []instance
	var walk func(raw json.RawMessage, where string, depth int) error
	walk = func(raw json.RawMessage, where string, depth int) error {
		if depth > moduleDepthLimit {
			return fmt.Errorf("%s nested more than %d module levels deep", where, moduleDepthLimit)
		}
		if !isObject(raw) {
			return errors.New(where + " is not an object")
		}
		var m stateModule
		if err := json.Unmarshal(raw, &m); err != nil {
			return fmt.Errorf("%s is not a module object: %v", where, err)
		}
		for i, raw := range m.Resources {
			at := where + ".resources[" + strconv.Itoa(i) + "]"
			if !isObject(raw) {
				return errors.New(at + " is not an object")
			}
			var r stateResource
			if err := json.Unmarshal(raw, &r); err != nil {
				return fmt.Errorf("%s is not a resource object: %v", at, err)
			}
			if r.Address == "" {
				return errors.New(at + " has no address")
			}
			if r.Mode == "data" && !keepData {
				continue
			}
			out = append(out, instance{address: r.Address, typ: r.Type, mode: r.Mode, values: r.Values, sensit: marks{r.SensitiveValues}, side: recorded})
		}
		for i, child := range m.ChildModules {
			if err := walk(child, where+".child_modules["+strconv.Itoa(i)+"]", depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root, where+"values.root_module", 0); err != nil {
		return nil, err
	}
	return out, nil
}

// Grants states every trust grant the plan holds: one or more per object
// the reader read of an instance the table names, never none, whether the
// plan sends, deletes, forgets or leaves the object as it is. at is the
// caller's clock, recorded on every evidence record and read from nowhere
// else; vocabulary is how the AWS parser learns what an issuer calls its
// claims, since this package imports no registry. A nil vocabulary knows
// no issuer, and every AWS claim is then Unknown with the parser's own
// caveat.
func (p Plan) Grants(at time.Time, vocabulary aws.ClaimVocabulary) []trust.Grant {
	a := artefact{
		source:           p.Source,
		origin:           FromPlan,
		formatVersion:    p.FormatVersion,
		terraformVersion: p.TerraformVersion,
		at:               at,
		vocabulary:       vocabulary,
		config:           p.config,
		prior:            p.prior,
		deferred:         p.deferred,
		addresses:        p.addresses,
		unread:           p.Unread,
	}
	// A plan that failed is incomplete by that failure; a plan that only
	// says it is incomplete is a targeted or partial one.
	switch {
	case p.Errored != nil && *p.Errored:
		a.flags = []trust.Anomaly{{Kind: PlanIncomplete, Construct: "errored", Message: "the plan is marked errored: true; it holds the actions planned before the failure, and the rest are not stated", Source: "plan"}}
	case p.Complete != nil && !*p.Complete:
		a.flags = []trust.Anomaly{{Kind: PlanIncomplete, Construct: "complete", Message: "the plan is marked complete: false, as a targeted or partial plan is, so resources it does not list are not absent; the grants read from it are a lower bound on the configuration's", Source: "plan"}}
	}
	return a.grants(p.instances)
}

// Grants states every trust grant the state records: one or more per
// instance the table names, never none. See Plan.Grants for the two
// parameters.
func (s State) Grants(at time.Time, vocabulary aws.ClaimVocabulary) []trust.Grant {
	a := artefact{
		source:           s.Source,
		origin:           FromState,
		formatVersion:    s.FormatVersion,
		terraformVersion: s.TerraformVersion,
		at:               at,
		vocabulary:       vocabulary,
		unread:           s.Unread,
	}
	return a.grants(s.instances)
}
