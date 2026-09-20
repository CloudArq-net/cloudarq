package terraform

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/evidence"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// Origin is which of Terraform's texts a Grant was read from. It is
// provenance, not inexactness: a plan states exactly what Terraform will
// send and a state exactly what it last recorded, and the set a Grant
// admits is exact whenever the cloud parser's is. What neither text is,
// is the deployed document, and every Terraform-sourced Grant says so in
// its TerraformOrigin anomaly and in the API of its evidence record,
// terraform/plan or terraform/state.
type Origin string

const (
	FromPlan  Origin = "plan"
	FromState Origin = "state"
)

// The anomaly kinds this reader defines beside the cloud parsers' own.
// The four that widen a grant to everything are always paired with a
// caveat carrying the same sentence; NoMembers narrows one to nothing,
// exactly; the rest are facts a reporter prints and admission does not
// depend on. Every anomaly names a
// construct, the attribute, member or flag it is about, and a source,
// the instance address or the artefact.
const (
	// TerraformOrigin is on every Grant: which text it was read from, and
	// that the deployed document was not fetched.
	TerraformOrigin = "terraform-origin"
	// KnownAfterApply marks a grant whose admission attribute, or a leaf
	// beneath it, the plan marks unknown: the value exists only after
	// apply, so the grant admits everything, declared, and the sentence
	// names what the expression references.
	KnownAfterApply = "known-after-apply"
	// AbsentAttribute marks a grant whose required admission attribute the
	// document leaves absent or null without marking it unknown: Terraform
	// writes both for an unset or unknown value, so nothing is stated and
	// the grant admits everything, declared.
	AbsentAttribute = "absent-attribute"
	// Malformed marks a grant whose admission attribute has a shape the
	// provider's schema does not give it, or a policy string that is not a
	// policy document, spelt as the cloud parsers spell the same defect.
	Malformed = "malformed"
	// UnboundMember marks the grant of a binding member no provider in the
	// document binds: a pool principal of a pool the document holds no
	// provider of, or a member that is not a pool principal at all. What
	// it admits is outside this document, so the grant admits everything,
	// declared.
	UnboundMember = "unbound-member"
	// NoMembers marks the grant of a binding that names no member at all:
	// the one grant a document can prove admits nobody, since the list
	// is known and empty, stated so that the resource is not silence.
	NoMembers = "no-members"
	// SensitiveValue marks a grant whose admission attribute the customer
	// marked sensitive: it was read and evaluated, and its quote and
	// evidence carry the reader's statement and the value's digest, never
	// the value.
	SensitiveValue = "sensitive-value"
	// RenderedDocument marks a grant whose unknown policy references a
	// data document the plan rendered before apply; the rendering is
	// attached as a second evidence record.
	RenderedDocument = "rendered-document"
	// TargetAfterApply marks a grant whose target attribute is known only
	// after apply, and says which address stands in for the target.
	TargetAfterApply = "target-after-apply"
	// PlannedDelete marks a grant read from the prior state of an object
	// the plan deletes.
	PlannedDelete = "planned-delete"
	// PlannedForget marks a grant read from the prior state of an object
	// the plan forgets: Terraform stops managing it and does not delete it,
	// so what it admits continues to exist.
	PlannedForget = "planned-forget"
	// NoChangeListed marks a grant read from the prior state of a resource
	// the plan lists no change for, as a refresh-only plan lists none and
	// a targeted plan lists only its targets; the plan leaves it as it is.
	NoChangeListed = "no-change-listed"
	// NoStatements marks the grant of a role whose policy projects no
	// statement: the one grant a policy proves admits nobody, stated so
	// that the role is not silence.
	NoStatements = "no-statements"
	// PlanIncomplete is on every grant of a plan marked incomplete or
	// errored: the plan is a lower bound on the configuration.
	PlanIncomplete = "plan-incomplete"
	// UnreadResource is on every grant of a document that holds instances
	// of a trust-shaped resource type the table does not map.
	UnreadResource = "unread-resource"
)

// api is the evidence API name of an origin: what a record of a file read
// is called, since the record type is documented as one API call and its
// verbatim response.
func (o Origin) api() string { return "terraform/" + string(o) }

// originSentence is the TerraformOrigin anomaly's message for an
// instance: which text it was read from, and what that text is.
func originSentence(inst instance) string {
	switch inst.side {
	case planned:
		return inst.address + " is read from the plan, as Terraform will send it, provider-normalised; the deployed resource was not fetched from the cloud"
	case deleted, forgotten, held:
		return inst.address + " is read from the plan's prior state, as Terraform last recorded it; the deployed resource was not fetched from the cloud"
	}
	return inst.address + " is read from the state, as Terraform last recorded it; the deployed resource was not fetched from the cloud"
}

// fate is the fact stamped on every grant of an object the plan does
// something to other than send: deletes it, forgets it, or leaves it as it
// is without listing it. Nothing for the object the plan sends or a state
// records.
func fate(inst instance) []trust.Anomaly {
	switch inst.side {
	case deleted:
		return []trust.Anomaly{{Kind: PlannedDelete, Construct: "delete", Message: "the plan deletes " + inst.address + "; the grant is what the prior state holds and will not exist once the plan is applied", Source: inst.address}}
	case forgotten:
		return []trust.Anomaly{{Kind: PlannedForget, Construct: "forget", Message: "the plan forgets " + inst.address + ": Terraform will discard its tracking information for it and will not delete it, so the object and what it admits continue to exist, unmanaged, once the plan is applied", Source: inst.address}}
	case held:
		return []trust.Anomaly{{Kind: NoChangeListed, Construct: "prior_state", Message: "the plan lists no change for " + inst.address + ", as a refresh-only plan lists none and a targeted plan lists only its targets; the grant is what the plan's prior state holds, which the plan leaves as it is", Source: inst.address}}
	}
	return nil
}

// listed spells one or more names for a sentence: "a", "a and b",
// "a, b and c".
func listed(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	last := len(names) - 1
	return strings.Join(names[:last], ", ") + " and " + names[last]
}

// plural is "is" or "are" for a list of subjects.
func plural(names []string, singular, several string) string {
	if len(names) == 1 {
		return singular
	}
	return several
}

// record builds the evidence record of one instance: the API named after
// the origin; canonical Params naming the artefact, its versions, the
// address, the attributes read, which member of a plan they were read
// from, the deposed key when there is one, and every identifier and the
// target attribute the document knows the value of; body as Bytes, sealed
// by the digest; and the caller's clock.
func (a artefact) record(inst instance, row ResourceType, body []byte, extra map[string]string) evidence.Record {
	params := map[string]any{
		"source":         a.source,
		"format_version": a.formatVersion,
		"address":        inst.address,
		"attributes":     row.names(),
	}
	if a.terraformVersion != "" {
		params["terraform_version"] = a.terraformVersion
	}
	if from := inst.side.from(); from != "" {
		params["from"] = from
	}
	if inst.deposed != "" {
		params["deposed"] = inst.deposed
	}
	for _, id := range row.Identifiers {
		if v, ok := inst.values.text(id); ok {
			params[id] = v
		}
	}
	if v, ok := inst.values.text(row.Target); ok && row.Target != "" && v != "" {
		params[row.Target] = v
	}
	for k, v := range extra {
		params[k] = v
	}
	return evidence.New(a.origin.api(), string(canonical(params)), evidence.StatusOK, body, a.at)
}

// statement is the reader's own account of what it read where no value
// can be quoted: the paths marked unknown and what their expressions
// reference; the attributes absent; the digest of a value marked
// sensitive; or the attributes that could not be read, with the digest of
// what the document writes for them. It is canonical JSON of the reader's
// making, never a customer document.
type statement map[string]any

func unknownStatement(paths []string, refs []string) []byte {
	if refs == nil {
		refs = []string{}
	}
	return canonical(statement{"unknown": paths, "references": refs})
}

func absentStatement(attributes []string) []byte {
	return canonical(statement{"absent": attributes})
}

// sensitiveStatement digests the value itself, so that the same value
// read where it is not marked seals the same digest.
func sensitiveStatement(attributes []string, value []byte) []byte {
	return canonical(statement{"sensitive": attributes, "sha256": digestOf(value)})
}

// malformedStatement digests the attribute's JSON as the document writes
// it, quotes and escapes included, since no value could be read from it;
// the finding is tied to the artefact without the reader repairing or
// re-rendering anything.
func malformedStatement(attributes []string, written []byte) []byte {
	return canonical(statement{"malformed": attributes, "sha256": digestOf(written)})
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// artefactAnomalies are the anomalies every grant of the document
// carries: the plan's flags, and the trust-shaped types the table does
// not map, one anomaly per type in type order.
func (a artefact) artefactAnomalies() []trust.Anomaly {
	out := slices.Clone(a.flags)
	counts := map[string]int{}
	for _, r := range a.unread {
		counts[r.Type]++
	}
	for _, typ := range sortedKeys(counts) {
		n := counts[typ]
		message := "the " + string(a.origin) + " holds " + strconv.Itoa(n) + " instance"
		if n == 1 {
			message += " of " + typ + ", which resembles a trust-bearing resource this reader does not map; it was not read"
		} else {
			message += "s of " + typ + ", which resembles a trust-bearing resource this reader does not map; they were not read"
		}
		out = append(out, trust.Anomaly{Kind: UnreadResource, Construct: typ, Message: message, Source: string(a.origin)})
	}
	return out
}

// stamp finishes a grant the reader states: the reading's facts, then the
// artefact-wide ones, then the origin, appended after whatever the cloud
// parser recorded, so that the parser's own list is left as it made it
// and the last word on every grant is where it came from.
func (a artefact) stamp(g trust.Grant, inst instance, reading []trust.Anomaly) trust.Grant {
	origin := trust.Anomaly{Kind: TerraformOrigin, Construct: string(a.origin), Message: originSentence(inst), Source: inst.address}
	g.Anomalies = slices.Concat(g.Anomalies, reading, a.wide, []trust.Anomaly{origin})
	return g
}
