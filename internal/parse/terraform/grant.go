package terraform

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/evidence"
	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/parse/azure"
	"github.com/CloudArq-net/cloudarq/internal/parse/gcp"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// artefact is one document being read into Grants: what every record
// and every sentence about it needs, and what the plan knows beside its
// instances, the configuration's references, the data documents it
// rendered, and the ones it deferred.
type artefact struct {
	source           string
	origin           Origin
	formatVersion    string
	terraformVersion string
	at               time.Time
	vocabulary       aws.ClaimVocabulary
	config           *configModule
	prior            map[string]instance
	deferred         map[string]bool
	addresses        []string // every instance address the plan lists, for resolving a target by reference
	unread           []Resource
	flags            []trust.Anomaly // what the plan's complete and errored flags say
	wide             []trust.Anomaly // the anomalies every grant of the document carries
}

// grants reads every instance in order. The providers are read first,
// because a binding's grant is the Meet of a member with each provider of
// its pool, wherever in the document the provider sits.
func (a artefact) grants(instances []instance) []trust.Grant {
	if a.vocabulary == nil {
		a.vocabulary = func(trust.IssuerRef, string) (trust.ClaimKey, bool) { return "", false }
	}
	a.wide = a.artefactAnomalies()
	providers := a.providers(instances)
	var out []trust.Grant
	for _, inst := range instances {
		row, _ := lookup(inst.typ)
		switch row.parser {
		case awsTrustPolicy:
			out = append(out, a.roleGrants(inst, row)...)
		case azureCredential:
			out = append(out, a.credentialGrants(inst, row)...)
		case gcpProvider:
			out = append(out, providers[inst.key()].own...)
		case gcpBinding:
			out = append(out, a.bindingGrants(inst, row, providers, instances)...)
		}
	}
	return out
}

// reading is what the reader established about one instance before any
// parser saw it: which admission attributes are unknown, at which paths,
// and what their expressions reference; which required ones are absent;
// which are marked sensitive; the target; and the facts to record on
// every grant of the instance.
type reading struct {
	inst      instance
	row       ResourceType
	unknown   []string // paths beneath the admission attributes marked unknown
	absent    []string // required admission attributes absent or null
	sensitive []string // admission attributes marked sensitive
	refs      []string // what the unknown attributes' expressions reference
	described bool     // the configuration describes the instance
	deferred  []string // data documents the policy references that are themselves read only after apply
	target    trust.TargetRef
	notes     []trust.Anomaly // facts about the instance, in the order every grant carries them
}

// inspect reads the marks and values of an instance against its row.
// after_unknown is consulted before after: a mark anywhere beneath an
// attribute makes it unknown whatever after holds, since the format
// documents an unknown leaf as omitted or null, indistinguishable from an
// absent one.
func (a artefact) inspect(inst instance, row ResourceType) reading {
	r := reading{inst: inst, row: row}
	var unknownAttributes []string
	for _, attr := range row.Attributes {
		if paths := consulted(attr, inst.unknown); len(paths) > 0 {
			r.unknown = append(r.unknown, paths...)
			unknownAttributes = append(unknownAttributes, attr.Name)
		} else if attr.Required && isNull(inst.values[attr.Name]) {
			r.absent = append(r.absent, attr.Name)
		}
		if len(consulted(attr, inst.sensit)) > 0 {
			r.sensitive = append(r.sensitive, attr.Name)
		}
	}
	var expressions map[string]any
	expressions, r.described = a.config.expressionsOf(inst.address)
	var refs []string
	for _, attr := range unknownAttributes {
		refs = append(refs, references(expressions, attr)...)
	}
	r.refs = withoutImplied(refs)
	r.target = trust.TargetRef{Kind: row.Kind, ID: inst.address}
	if row.Target != "" {
		var note *trust.Anomaly
		r.target.ID, note = a.resolveTarget(inst, row, expressions)
		if note != nil {
			r.notes = append(r.notes, *note)
		}
	}
	r.notes = append(r.notes, fate(inst)...)
	return r
}

// sensitiveNote is the fact that admission attributes were marked
// sensitive, when they were: read and evaluated but not quoted when a
// parser read the value, and with no value read when the value was
// unknown, absent or could not be read. A mark is never dropped because
// there was nothing to redact.
func (r reading) sensitiveNote(read bool) []trust.Anomaly {
	if len(r.sensitive) == 0 {
		return nil
	}
	return []trust.Anomaly{{Kind: SensitiveValue, Construct: strings.Join(r.sensitive, ", "), Message: sensitiveSentence(r, read), Source: r.inst.address}}
}

// consulted lists the marked paths beneath an attribute that the reader
// reads.
func consulted(attr Attribute, m marks) []string {
	var out []string
	for _, path := range m.paths(attr.Name) {
		if attr.consults(path) {
			out = append(out, path)
		}
	}
	return out
}

// resolveTarget names the target of a credential or binding. The value of
// the target attribute, when the document states it; otherwise the
// address of the one resource instance the expression references, so
// that every credential of an application created in the same plan
// resolves to one target; otherwise the instance's own address, with the
// consequence stated.
func (a artefact) resolveTarget(inst instance, row ResourceType, expressions map[string]any) (string, *trust.Anomaly) {
	why := row.Target + " of " + inst.address + " is absent from the document"
	if inst.unknown.marked(row.Target) {
		why = row.Target + " of " + inst.address + " is known only after apply"
	} else if v, ok := inst.values.text(row.Target); ok && v != "" {
		return v, nil
	}
	var candidates []string
	for _, ref := range references(expressions, row.Target) {
		local, ok := resourceReference(ref)
		if !ok {
			continue
		}
		absolute := modulePrefix(inst.address) + local
		for _, address := range a.addresses {
			if (address == absolute || strings.HasPrefix(address, absolute+"[")) && !slices.Contains(candidates, address) {
				candidates = append(candidates, address)
			}
		}
	}
	if len(candidates) == 1 {
		return candidates[0], &trust.Anomaly{Kind: TargetAfterApply, Construct: row.Target, Message: why + "; the target is named by the address of the resource the expression references, " + candidates[0], Source: inst.address}
	}
	return inst.address, &trust.Anomaly{Kind: TargetAfterApply, Construct: row.Target, Message: why + " and the expression references no single resource instance of this " + string(a.origin) + "; the resource's own address stands in for the target, so two resources on one target may read as two targets", Source: inst.address}
}

// widening is the grant an instance states when its admission attributes
// cannot be read: everything, declared by a caveat, with the reason as
// the first anomaly and the reader's statement as the evidence. It is
// false when the attributes can be read.
func (a artefact) widening(r reading) (trust.Grant, bool) {
	switch {
	case len(r.unknown) > 0:
		message := listed(r.unknown) + " of " + r.inst.address + " " + plural(r.unknown, "is", "are") + " known only after apply; " + r.referencesClause() + ", so what the grant admits is not stated and it is read as admitting everything"
		return a.everything(r, trust.Anomaly{Kind: KnownAfterApply, Construct: strings.Join(r.unknown, ", "), Message: message, Source: r.inst.address}, unknownStatement(r.unknown, r.refs)), true
	case len(r.absent) > 0:
		message := listed(r.absent) + " of " + r.inst.address + " " + plural(r.absent, "is", "are") + " absent from the " + string(a.origin) + ", which Terraform writes for a value that is unset or unknown; what the grant admits is not stated and it is read as admitting everything"
		return a.everything(r, trust.Anomaly{Kind: AbsentAttribute, Construct: strings.Join(r.absent, ", "), Message: message, Source: r.inst.address}, absentStatement(r.absent)), true
	}
	return trust.Grant{}, false
}

// referencesClause says what the configuration knows about the unknown
// value's expression: the references it lists, that it lists none, or
// that it does not describe the instance at all.
func (r reading) referencesClause() string {
	var clause string
	switch {
	case len(r.refs) > 0:
		clause = "the expression references " + listed(r.refs)
	case r.described:
		clause = "the configuration names no reference for it"
	default:
		clause = "the configuration does not describe it"
	}
	for _, doc := range r.deferred {
		clause += ", and the data document " + doc + " is itself read only after apply"
	}
	return clause
}

// malformed is the grant of an instance whose attributes the reader could
// not read, why saying what was met. body is the evidence: the document
// the reader built and the parser refused, or the reader's statement
// naming the attribute with the digest of what the document writes for
// it, when no document could be built.
func (a artefact) malformed(r reading, attributes []string, why string, body []byte) trust.Grant {
	message := listed(attributes) + " of " + r.inst.address + " " + why + "; " + plural(attributes, "it is", "they are") + " not read and the grant is read as admitting everything"
	return a.everything(r, trust.Anomaly{Kind: Malformed, Construct: strings.Join(attributes, ", "), Message: message, Source: r.inst.address}, body)
}

// everything is a grant that admits everything, declared by the anomaly's
// sentence as its caveat, with the issuer the document states when it
// states one and the reader's statement as its Source and evidence.
func (a artefact) everything(r reading, why trust.Anomaly, body []byte) trust.Grant {
	g := trust.Grant{
		Target:     r.target,
		Issuer:     a.issuerOf(r.inst, r.row),
		Admits:     eval.Everything().WithCaveat(eval.Caveat{Reason: why.Message, Source: why.Source}),
		Effect:     trust.Allow,
		Anomalies:  []trust.Anomaly{why},
		Provenance: []evidence.Record{a.record(r.inst, r.row, body, nil)},
		Source:     body,
	}
	return a.stamp(g, r.inst, slices.Concat(r.sensitiveNote(false), r.notes))
}

// issuerOf is the issuer a credential or provider names when its
// admission cannot be read: the issuer attribute, normalised, when the
// document states it; the AWS pseudo-issuer for an AWS provider; and
// nothing otherwise, which the join pairs with every counterparty. The
// cloud parsers' facts about an issuer's spelling are not repeated here:
// a grant read as everything carries the one fact that matters.
func (a artefact) issuerOf(inst instance, row ResourceType) trust.IssuerRef {
	var written string
	switch row.parser {
	case azureCredential:
		written, _ = inst.values.text("issuer")
	case gcpProvider:
		if len(inst.list("aws")) > 0 {
			return aws.AWSPrincipalIssuer
		}
		if oidc := inst.list("oidc"); len(oidc) > 0 {
			written, _ = oidc[0].text("issuer_uri")
		}
	default:
		return ""
	}
	issuer, ok := trust.NormaliseIssuer(strings.TrimSpace(written))
	if !ok {
		return ""
	}
	return issuer
}

// list reads a block attribute as the list of objects Terraform writes
// for one: nil when it is absent, null, not a list, or holds anything
// but objects.
func (inst instance) list(attribute string) []members {
	var out []members
	if raw, ok := inst.values[attribute]; ok && json.Unmarshal(raw, &out) == nil {
		return out
	}
	return nil
}

// finish attaches the instance's record to every grant a parser stated
// for it, redacts the quote when the value is marked sensitive, and
// stamps the reader's facts on. body is what the parser read.
func (a artefact) finish(r reading, grants []trust.Grant, body []byte, extra []evidence.Record) []trust.Grant {
	record := a.record(r.inst, r.row, body, nil)
	if len(r.sensitive) > 0 {
		redaction := sensitiveStatement(r.sensitive, body)
		record = a.record(r.inst, r.row, redaction, nil)
		for i := range grants {
			grants[i].Source = redaction
		}
	}
	notes := slices.Concat(r.sensitiveNote(true), r.notes)
	for i := range grants {
		grants[i].Provenance = slices.Concat([]evidence.Record{record}, extra)
		grants[i] = a.stamp(grants[i], r.inst, notes)
	}
	return grants
}

// sensitiveSentence says that a value was read and is not quoted, or
// that no value was read, for one attribute or several.
func sensitiveSentence(r reading, read bool) string {
	is, was, its, it := "is", "it was", "its", "it"
	if len(r.sensitive) > 1 {
		is, was, its, it = "are", "they were", "their", "them"
	}
	head := listed(r.sensitive) + " of " + r.inst.address + " " + is + " marked sensitive; "
	if !read {
		return head + "no value of " + it + " was read and none is quoted"
	}
	return head + was + " read and evaluated, and " + is + " not quoted: the evidence carries " + its + " digest"
}

// roleGrants reads an aws_iam_role: the policy string, as written, handed
// to the AWS parser, whose grants carry the parser's facts about the
// document as a whole beside their own, since the grant is the only thing
// this reader hands on. A policy the parser projects no statement from
// states one grant that admits nothing, exactly, so that the role is not
// silence: an empty Statement list, or none, is the one emptiness a
// policy proves. A policy known only after apply that references a data
// document the plan rendered gets the rendering as evidence: it is what
// the policy is built from, not what the policy is, which a transformation
// between the two may change.
func (a artefact) roleGrants(inst instance, row ResourceType) []trust.Grant {
	r := a.inspect(inst, row)
	renderings, rendered := a.renderings(&r)
	if g, widened := a.widening(r); widened {
		// The renderings follow the widening they qualify, before the
		// reader's other facts.
		g.Provenance = append(g.Provenance, renderings...)
		g.Anomalies = slices.Concat(g.Anomalies[:1], rendered, g.Anomalies[1:])
		return []trust.Grant{g}
	}
	attributes := []string{"assume_role_policy"}
	written := inst.values["assume_role_policy"]
	policy, err := stringValue(written)
	if err != nil {
		return []trust.Grant{a.malformed(r, attributes, err.Error(), malformedStatement(attributes, written))}
	}
	doc, err := aws.ParseTrustPolicy([]byte(policy))
	if err != nil {
		return []trust.Grant{a.malformed(r, attributes, "is not a trust policy document ("+err.Error()+")", malformedStatement(attributes, written))}
	}
	grants := doc.Grants(r.target, a.vocabulary)
	if len(grants) == 0 {
		why := trust.Anomaly{Kind: NoStatements, Construct: "Statement", Message: "assume_role_policy of " + inst.address + " projects no statement, so it grants nobody anything: the one emptiness a policy proves", Source: inst.address}
		grants = []trust.Grant{{Target: r.target, Admits: eval.Nothing(), Effect: trust.Allow, Anomalies: []trust.Anomaly{why}, Source: []byte(policy)}}
	}
	for i := range grants {
		grants[i].Anomalies = append(grants[i].Anomalies, doc.Anomalies...)
	}
	return a.finish(r, grants, []byte(policy), nil)
}

// renderings are the data documents a role's unknown policy references
// and the plan rendered before apply, each as an evidence record with the
// fact that names it; one the plan marks sensitive is redacted to its
// digest. A document the plan reads only after apply is noted on the
// reading for the widening sentence instead, whatever a prior state holds
// under its address: that rendering is stale.
func (a artefact) renderings(r *reading) ([]evidence.Record, []trust.Anomaly) {
	var records []evidence.Record
	var facts []trust.Anomaly
	for _, ref := range r.refs {
		local, ok := resourceReference(ref)
		if !ok || !strings.HasPrefix(local, "data.aws_iam_policy_document.") {
			continue
		}
		absolute := modulePrefix(r.inst.address) + local
		switch doc, ok := a.prior[absolute]; {
		case a.deferred[absolute]:
			r.deferred = append(r.deferred, absolute)
		case ok:
			text, err := stringValue(doc.values["json"])
			if err != nil {
				continue
			}
			body := []byte(text)
			how := ", whose json the plan rendered before apply; the rendering is attached as evidence, and "
			if doc.sensit.marked("json") {
				body = sensitiveStatement([]string{"json"}, body)
				how = ", whose json the plan rendered before apply and marks sensitive; the rendering is attached as evidence redacted to its digest, and "
			}
			records = append(records, a.record(doc, ResourceType{Attributes: []Attribute{{Name: "json"}}}, body, map[string]string{"rendering_for": r.inst.address}))
			facts = append(facts, trust.Anomaly{Kind: RenderedDocument, Construct: absolute, Message: "the expression references " + absolute + how + "assume_role_policy of " + r.inst.address + " may differ from it", Source: r.inst.address})
		}
	}
	return records, facts
}

// credentialGrants reads a federated identity credential of either Azure
// provider into the document the Azure parser reads: the credential
// members under Graph's names, the labels beside them, and nothing
// else. The values are copied as written; a member of the wrong type is
// the parser's to report, in its own words.
func (a artefact) credentialGrants(inst instance, row ResourceType) []trust.Grant {
	r := a.inspect(inst, row)
	if g, widened := a.widening(r); widened {
		return []trust.Grant{g}
	}
	doc := map[string]any{}
	for _, attr := range row.Attributes {
		if raw, ok := inst.values[attr.Name]; ok && !isNull(raw) {
			member := attr.Name
			if member == "audience" {
				// Resource Manager's list is Graph's audiences.
				member = "audiences"
			}
			doc[member] = raw
		}
	}
	a.label(doc, inst, row)
	body := canonical(doc)
	credential, err := azure.ParseFederatedCredential(body)
	if err != nil {
		return []trust.Grant{a.malformed(r, row.names(), "cannot be read as a credential ("+err.Error()+")", body)}
	}
	return a.finish(r, credential.Grants(r.target), body, nil)
}

// label copies the labelling attributes of an instance into a document
// under the API's names, as written, when the document states them as
// strings other than the empty one Terraform writes for an unset
// optional string.
func (a artefact) label(doc map[string]any, inst instance, row ResourceType) {
	for attr, member := range row.labels {
		if raw, ok := inst.values[attr]; ok && isString(raw) && string(bytes.TrimSpace(raw)) != `""` {
			doc[member] = raw
		}
	}
}

// providerReading is one google_iam_workload_identity_pool_provider as
// read once for the whole document: its own grant, and what a binding
// needs to be met with it.
type providerReading struct {
	own      []trust.Grant
	provider gcp.Provider
	poolID   string // workload_identity_pool_id when the document states it
	record   evidence.Record
	widened  *trust.Grant // the provider's grant when it could not be read, whose anomaly every binding on it inherits
	redacted []byte       // the statement that stands for the provider when it is marked sensitive
}

// providers reads every provider of the document, by instance key.
func (a artefact) providers(instances []instance) map[string]providerReading {
	out := map[string]providerReading{}
	for _, inst := range instances {
		row, _ := lookup(inst.typ)
		if row.parser == gcpProvider {
			out[inst.key()] = a.readProvider(inst, row)
		}
	}
	return out
}

// key tells one object of a plan from another: the deposed object of an
// address is listed beside its current one, and a replace that forgets
// reads the created object and the forgotten one.
func (inst instance) key() string { return inst.address + "|" + inst.deposed + "|" + inst.side.from() }

func (a artefact) readProvider(inst instance, row ResourceType) providerReading {
	r := a.inspect(inst, row)
	var p providerReading
	p.poolID, _ = inst.values.text("workload_identity_pool_id")
	provider, body, unread := a.parseProvider(r)
	if unread != nil {
		p.own, p.widened, p.record = []trust.Grant{*unread}, unread, unread.Provenance[0]
		return p
	}
	p.provider = provider
	p.own = a.finish(r, provider.Grants(r.target), body, nil)
	p.record = p.own[0].Provenance[0]
	if len(r.sensitive) > 0 {
		p.redacted = p.record.Bytes
	}
	return p
}

// parseProvider is the provider an instance states and the document it
// was built from, or, when the instance cannot be read, the grant that
// stands for it.
func (a artefact) parseProvider(r reading) (gcp.Provider, []byte, *trust.Grant) {
	if g, widened := a.widening(r); widened {
		return gcp.Provider{}, nil, &g
	}
	body, attribute, why := a.buildProvider(r.inst, r.row)
	if why != "" {
		g := a.malformed(r, []string{attribute}, why, malformedStatement([]string{attribute}, r.inst.values[attribute]))
		return gcp.Provider{}, nil, &g
	}
	provider, err := gcp.ParseProvider(body)
	if err != nil {
		g := a.malformed(r, r.row.names(), "cannot be read as a provider ("+err.Error()+")", body)
		return gcp.Provider{}, nil, &g
	}
	return provider, body, nil
}

// buildProvider builds the provider document the GCP parser reads from
// the attributes Terraform writes: the four provider_config blocks are
// lists of at most one object, which become the API's objects, the
// mapping is copied with its keys sorted, and the scalars as written.
// A block of another shape cannot be built and is named with the reason.
func (a artefact) buildProvider(inst instance, row ResourceType) (body []byte, attribute, why string) {
	doc := map[string]any{}
	if raw, ok := inst.values["attribute_condition"]; ok && !isNull(raw) {
		doc["attributeCondition"] = raw
	}
	if raw, ok := inst.values["attribute_mapping"]; ok && !isNull(raw) {
		var mapping map[string]json.RawMessage
		if err := json.Unmarshal(raw, &mapping); err != nil {
			return nil, "attribute_mapping", "is " + jsonKind(raw) + ", not an object"
		}
		doc["attributeMapping"] = mapping
	}
	if raw, ok := inst.values["disabled"]; ok && !isNull(raw) {
		var disabled bool
		if err := json.Unmarshal(raw, &disabled); err != nil {
			return nil, "disabled", "is " + jsonKind(raw) + ", not a boolean"
		}
		if disabled {
			doc["disabled"] = true
		}
	}
	for _, block := range []string{"aws", "oidc", "saml", "x509"} {
		raw, ok := inst.values[block]
		if !ok || isNull(raw) {
			continue
		}
		var items []members
		if err := json.Unmarshal(raw, &items); err != nil || len(items) > 1 {
			return nil, block, "is not a list of at most one object, which the provider's schema makes it"
		}
		if len(items) == 0 {
			continue
		}
		switch block {
		case "oidc":
			inner := map[string]any{}
			if v, ok := items[0]["issuer_uri"]; ok && !isNull(v) {
				inner["issuerUri"] = v
			}
			// An empty list is how Terraform writes an unset list in a state
			// and null how it writes one in a plan; Google reads both as no
			// audience set.
			if v, ok := items[0]["allowed_audiences"]; ok && !isNull(v) && string(bytes.TrimSpace(v)) != "[]" {
				inner["allowedAudiences"] = v
			}
			doc["oidc"] = inner
		case "aws":
			inner := map[string]any{}
			if v, ok := items[0]["account_id"]; ok && !isNull(v) {
				inner["accountId"] = v
			}
			doc["aws"] = inner
		default:
			doc[block] = items[0]
		}
	}
	a.label(doc, inst, row)
	return canonical(doc), "", ""
}

// bindingGrants reads a binding on a service account: the policy the
// three resource types state, built or copied, handed to the GCP parser
// for its members, each of which is met with every provider of its pool
// the document holds. A member of a pool with no provider here, or one
// that is not a pool principal, states a grant that admits everything,
// declared: what it admits is decided by documents this one does not
// hold, and a member that vanished would be silence. A binding with no
// member at all states one grant that admits nothing, exactly.
func (a artefact) bindingGrants(inst instance, row ResourceType, providers map[string]providerReading, instances []instance) []trust.Grant {
	r := a.inspect(inst, row)
	if g, widened := a.widening(r); widened {
		return []trust.Grant{g}
	}
	body, attribute, why := buildPolicy(inst)
	if why != "" {
		return []trust.Grant{a.malformed(r, []string{attribute}, why, malformedStatement([]string{attribute}, inst.values[attribute]))}
	}
	members, err := gcp.ParseMembers(body)
	if err != nil {
		return []trust.Grant{a.malformed(r, row.names(), "cannot be read as an IAM policy ("+err.Error()+")", body)}
	}
	if len(members) == 0 {
		why := trust.Anomaly{Kind: NoMembers, Construct: "members", Message: inst.address + " names no member, so it grants nobody anything; the list is known and empty, which is the one emptiness a document proves", Source: inst.address}
		g := trust.Grant{Target: r.target, Admits: eval.Nothing(), Effect: trust.Allow, Anomalies: []trust.Anomaly{why}, Source: body}
		return a.finish(r, []trust.Grant{g}, body, nil)
	}
	var out []trust.Grant
	for _, m := range members {
		bound := false
		for _, candidate := range instances {
			p, isProvider := providers[candidate.key()]
			if !isProvider || !p.mayHold(m) {
				continue
			}
			g, ok := a.bind(r, p, m, body)
			if !ok {
				continue
			}
			bound = true
			out = append(out, g)
		}
		if !bound {
			out = append(out, a.unbound(r, m, body))
		}
	}
	return out
}

// mayHold reports whether a member may be a binding on this provider's
// pool: the member names a pool, and its pool id is the provider's or
// the provider's is not stated. The project and location are the
// parser's to weigh; the pool id is what a create plan knows before the
// provider has a name.
func (p providerReading) mayHold(m gcp.Member) bool {
	if m.Pool == "" {
		return false
	}
	poolID := m.Pool[strings.LastIndex(m.Pool, "/")+1:]
	return p.poolID == "" || p.poolID == poolID
}

// bind is the grant one member gives on one provider: what the parser
// makes of the Meet, or, for a provider that could not be read, the
// provider's own widening under the binding's target.
func (a artefact) bind(r reading, p providerReading, m gcp.Member, body []byte) (trust.Grant, bool) {
	if p.widened != nil {
		g := trust.Grant{
			Target:    r.target,
			Issuer:    p.widened.Issuer,
			Admits:    p.widened.Admits,
			Effect:    trust.Allow,
			Anomalies: p.widened.Anomalies[:1],
			Source:    body,
		}
		return a.finish(r, []trust.Grant{g}, body, []evidence.Record{p.record})[0], true
	}
	g, ok := p.provider.Bind(m, r.target)
	if !ok {
		return trust.Grant{}, false
	}
	if p.redacted != nil {
		g.Source = p.redacted
	}
	return a.finish(r, []trust.Grant{g}, body, []evidence.Record{p.record})[0], true
}

// unbound is the grant of a member no provider in the document binds.
func (a artefact) unbound(r reading, m gcp.Member, body []byte) trust.Grant {
	message := "the member " + m.Text + " is not a workload identity pool principal; what it admits is outside what this reader models and the grant is read as admitting everything"
	if m.Pool != "" {
		message = "the member " + m.Text + " names the pool " + m.Pool + ", and no provider of that pool is in this " + string(a.origin) + "; what the pool admits is not stated and the grant is read as admitting everything"
	}
	why := trust.Anomaly{Kind: UnboundMember, Construct: m.Text, Message: message, Source: r.inst.address}
	g := trust.Grant{
		Target:    r.target,
		Admits:    eval.Everything().WithCaveat(eval.Caveat{Reason: why.Message, Source: why.Source}),
		Effect:    trust.Allow,
		Anomalies: []trust.Anomaly{why},
		Source:    body,
	}
	return a.finish(r, []trust.Grant{g}, body, nil)[0]
}

// buildPolicy builds the IAM policy the GCP parser reads: the policy_data
// string as written for google_service_account_iam_policy, and for the
// member and binding resources one binding with the role, the member or
// members as written, and the condition block's expression, title and
// description when the block is set.
func buildPolicy(inst instance) (body []byte, attribute, why string) {
	if raw, ok := inst.values["policy_data"]; ok {
		policy, err := stringValue(raw)
		if err != nil {
			return nil, "policy_data", err.Error()
		}
		return []byte(policy), "", ""
	}
	binding := map[string]any{"role": inst.values["role"]}
	if raw, ok := inst.values["members"]; ok {
		binding["members"] = raw
	} else {
		binding["members"] = []any{inst.values["member"]}
	}
	if raw, ok := inst.values["condition"]; ok && !isNull(raw) {
		var items []members
		if err := json.Unmarshal(raw, &items); err != nil || len(items) > 1 {
			return nil, "condition", "is not a list of at most one object, which the provider's schema makes it"
		}
		if len(items) == 1 {
			condition := map[string]any{}
			for _, member := range []string{"description", "expression", "title"} {
				if v, ok := items[0][member]; ok && !isNull(v) {
					condition[member] = v
				}
			}
			binding["condition"] = condition
		}
	}
	return canonical(map[string]any{"bindings": []any{binding}}), "", ""
}
