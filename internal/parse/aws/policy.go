package aws

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// The anomaly kinds this parser defines beside trust.Unmodelled. The first
// two change what a grant admits and are always paired with a caveat; the
// rest are facts a reporter prints and admission does not depend on.
const (
	// DuplicateKey is a member written more than once at some depth. A JSON
	// decoder keeps one copy and the deployed policy may carry either, so
	// whatever the copies decided is not known.
	DuplicateKey = "duplicate-key"
	// Malformed is a member of the wrong JSON type, a value the grammar does
	// not allow, or an effect that is not exactly Allow or Deny.
	Malformed = "malformed"
	// AnyPrincipal marks a statement that applies to every principal.
	AnyPrincipal = "any-principal"
	// ServicePrincipal marks a grant to an AWS service rather than to an
	// external identity.
	ServicePrincipal = "service-principal"
	// NotAnAssumeAction marks a statement whose actions let a principal of
	// the grant's kind assume nothing, whatever else it says.
	NotAnAssumeAction = "not-an-assume-action"
	// VariableIsLiteral marks a "${...}" that AWS reads as literal text
	// because the document's Version does not resolve policy variables: the
	// set is exact, and the condition may not do what it looks like it does.
	VariableIsLiteral = "variable-is-literal"
)

// Document is a trust policy read in full: every statement in document
// order, whatever the parser made of it, and every fact about the document
// itself that the evaluator or the reporter may need. Anomalies are never
// warnings to be logged and dropped.
//
// Version is the Version member as written, or empty when the document has
// none, has several, or has one that is not a string.
type Document struct {
	Version    string
	Statements []Statement
	Anomalies  []trust.Anomaly
	variables  variableMode
}

// Statement is one statement as written. Raw is the statement's own bytes,
// from its opening brace to its closing one, cut from a copy of the input:
// a finding quotes the customer's policy, never a re-rendering of it.
type Statement struct {
	Sid        string
	Effect     trust.Effect
	Principals Principals
	Actions    ActionSet
	Conditions ConditionBlock
	Raw        json.RawMessage
	// findings is what reading the statement as a whole recorded: the
	// anomalies every grant of it carries, and the caveats that go with
	// the ones that change what the grants admit.
	findings findings
}

// findings collects anomalies and, for each that changes what a grant
// admits, the caveat that declares it. An anomaly states a fact about the
// document; a caveat says what the fact does to the admitted set, so the
// two stay paired and Exact answers from the set alone. A fact widens when
// nothing about the set can be evaluated, and doubts when the set can be
// evaluated but is only an upper bound: a claim of it is Unknown, or the
// deployed policy may not carry it.
type findings struct {
	anomalies []trust.Anomaly
	widenings []eval.Caveat // the set is everything, declared
	doubts    []eval.Caveat // the set stands, as an upper bound
}

// widen records a fact that leaves the whole set unevaluated: every grant
// it applies to admits everything, declared by a caveat with no claim.
func (f *findings) widen(a trust.Anomaly) {
	f.anomalies = append(f.anomalies, a)
	f.widenings = append(f.widenings, eval.Caveat{Reason: a.Message, Source: a.Source})
}

// doubt records a fact that leaves the set an upper bound rather than the
// answer: a construct outside the grammar beside constraints that can be
// read, a statement the deployed policy may not carry, or a principal
// whose identity is Unknown on one claim. The set is kept, because it is a
// tighter bound than everything, and declared on the anomaly's claim.
func (f *findings) doubt(a trust.Anomaly) {
	f.anomalies = append(f.anomalies, a)
	f.doubts = append(f.doubts, eval.Caveat{Claim: a.Claim, Reason: a.Message, Source: a.Source})
}

// note records a fact that changes nothing about what the set admits.
func (f *findings) note(a trust.Anomaly) { f.anomalies = append(f.anomalies, a) }

// caveats is every caveat the findings declare.
func (f findings) caveats() []eval.Caveat { return slices.Concat(f.widenings, f.doubts) }

// clone is a copy that shares nothing, so that two grants built from one
// principal cannot write into each other's lists.
func (f findings) clone() findings {
	return findings{anomalies: slices.Clone(f.anomalies), widenings: slices.Clone(f.widenings), doubts: slices.Clone(f.doubts)}
}

// variableMode is how a value holding "${" is read, which the document's
// Version decides: the 2012 language resolves policy variables per request;
// the 2008 language, and a document with no Version, read the text as
// written; a Version this parser cannot read leaves the question open.
type variableMode int

const (
	variablesLiteral variableMode = iota
	variablesResolved
	variablesUncertain
)

// ParseTrustPolicy is total. It returns an error only for input that is not
// one JSON object: invalid JSON or UTF-8, a byte order mark, a lone UTF-16
// surrogate escape, empty input, bytes after the document, or a root of
// another type. Everything else is a Document, in which whatever could not
// be understood is represented as Unknown with the reason.
//
// The input is copied once and every Raw slices the copy, so a caller that
// reuses its buffer cannot rewrite the Document.
func ParseTrustPolicy(raw []byte) (Document, error) {
	root, err := parseTree(bytes.Clone(raw))
	if err != nil {
		return Document{}, fmt.Errorf("parse trust policy: %w", err)
	}
	if root.kind != kindObject {
		return Document{}, fmt.Errorf("parse trust policy: the document is %s, not an object", root.kind)
	}
	return parseDocument(root), nil
}

// parseDocument reads the members the IAM grammar defines at the top level.
// A member written twice is a fact about the document, recorded and handled
// member by member, never resolved by keeping one copy. A member the grammar
// does not define may be a misspelled Statement, and what it grants is not
// known: it becomes an unreadable statement, so that the document projects
// a grant admitting everything, declared, rather than reading as a policy
// that trusts nobody.
func parseDocument(root *value) Document {
	var d Document
	hasStatement := false
	groups := groupMembers(root, exactName)
	for i := range groups {
		g := &groups[i]
		switch g.name {
		case "Version":
			d.parseVersion(g)
		case "Id":
			d.parseID(g)
		case "Statement":
			hasStatement = true
			d.parseStatements(g)
		default:
			for _, v := range g.values {
				d.appendUnreadable(v, trust.Anomaly{Kind: Malformed, Construct: g.name, Message: "the document member " + strconv.QuoteToASCII(g.name) + " is not one the IAM policy grammar defines, so what it grants is not known"})
			}
		}
	}
	if !hasStatement {
		d.Anomalies = append(d.Anomalies, trust.Anomaly{Kind: Malformed, Construct: "Statement", Message: "the document has no Statement member; the IAM grammar requires one", Source: "document"})
	}
	return d
}

// appendUnreadable adds a statement the parser could not read as one, for
// the reason a says, at the next statement index. It admits everything,
// declared: what a value outside the grammar grants is not known.
func (d *Document) appendUnreadable(v *value, a trust.Anomaly) {
	a.Source = "statement[" + strconv.Itoa(len(d.Statements)) + "]"
	s := Statement{Raw: v.bytes(), Effect: trust.EffectUnknown, Principals: nobody(), Actions: ActionSet{unknown: true}}
	s.findings.widen(a)
	d.Statements = append(d.Statements, s)
}

// parseVersion settles how policy variables are read. The two language
// versions AWS documents each say; anything else leaves it open, and open
// means every value holding "${" is Unknown.
func (d *Document) parseVersion(g *memberGroup) {
	if len(g.values) > 1 {
		d.Anomalies = append(d.Anomalies, trust.Anomaly{Kind: DuplicateKey, Construct: "Version", Message: "the member Version appears more than once in the document; policy variables are read as unresolved", Source: "document"})
		d.variables = variablesUncertain
		return
	}
	v := g.values[0]
	if v.kind != kindString {
		d.Anomalies = append(d.Anomalies, trust.Anomaly{Kind: Malformed, Construct: "Version", Message: "Version is " + describe(v) + ", not a string; policy variables are read as unresolved", Source: "document"})
		d.variables = variablesUncertain
		return
	}
	d.Version = v.text
	switch v.text {
	case "2012-10-17":
		d.variables = variablesResolved
	case "2008-10-17":
		d.variables = variablesLiteral
	default:
		d.Anomalies = append(d.Anomalies, trust.Anomaly{Kind: Malformed, Construct: "Version", Message: "Version " + strconv.QuoteToASCII(v.text) + ` is neither "2012-10-17" nor "2008-10-17"; policy variables are read as unresolved`, Source: "document"})
		d.variables = variablesUncertain
	}
}

// parseID checks the shape of Id, which nothing here reads: a policy id is
// for the customer's records, and a mis-shaped one is worth a sentence.
func (d *Document) parseID(g *memberGroup) {
	if len(g.values) > 1 {
		d.Anomalies = append(d.Anomalies, trust.Anomaly{Kind: DuplicateKey, Construct: "Id", Message: "the member Id appears more than once in the document", Source: "document"})
	}
	for _, v := range g.values {
		if v.kind != kindString {
			d.Anomalies = append(d.Anomalies, trust.Anomaly{Kind: Malformed, Construct: "Id", Message: "Id is " + describe(v) + ", not a string", Source: "document"})
		}
	}
}

// parseStatements reads every statement of every copy of the Statement
// member. An object is a list of one, and so is anything else: a number or
// a string where the grammar wants an object or a list is one statement
// that cannot be read, exactly as it would be inside brackets. Nothing here
// skips a statement: one that cannot be read becomes a Statement all the
// same, and projects a grant that admits everything, declared.
//
// When the member is written twice, every statement of every copy is kept,
// because dropping either is what a decoder does; and every one of them
// carries a doubt, because which copy the deployed policy holds is not
// known, so an Allow among them is an upper bound and a Deny cannot be
// applied.
func (d *Document) parseStatements(g *memberGroup) {
	duplicated := len(g.values) > 1
	if duplicated {
		d.Anomalies = append(d.Anomalies, trust.Anomaly{Kind: DuplicateKey, Construct: "Statement", Message: "the member Statement appears more than once in the document; every statement in every copy is kept", Source: "document"})
	}
	read := 0
	for _, v := range g.values {
		items := []*value{v}
		if v.kind == kindArray {
			items = v.items
		}
		for _, item := range items {
			src := "statement[" + strconv.Itoa(len(d.Statements)) + "]"
			s := parseStatement(item, src)
			if duplicated {
				s.findings.doubt(trust.Anomaly{Kind: DuplicateKey, Construct: "Statement", Message: "the member Statement appears more than once in the document; a JSON decoder keeps one copy and the deployed policy may carry either, so whether this statement is deployed is not known", Source: src})
			}
			d.Statements = append(d.Statements, s)
			read++
		}
	}
	if read == 0 {
		d.Anomalies = append(d.Anomalies, trust.Anomaly{Kind: Malformed, Construct: "Statement", Message: "Statement is an empty list, so the document grants nothing", Source: "document"})
	}
}

// statementMembers are the statement members this parser reads. Any other,
// Resource and NotResource included, leaves the statement unevaluated: what
// an element outside this set does to a role trust policy is not something
// this parser states.
var statementMembers = map[string]bool{
	"Sid": true, "Effect": true, "Principal": true, "NotPrincipal": true,
	"Action": true, "NotAction": true, "Condition": true,
}

// parseStatement reads one statement. Every member is read by its own rule
// and every rule is total, so the only way a statement can fail to project
// a grant is to be dropped here, and nothing here drops one.
func parseStatement(v *value, src string) Statement {
	s := Statement{Raw: v.bytes()}
	if v.kind != kindObject {
		s.Effect = trust.EffectUnknown
		s.Principals = nobody()
		s.Actions = ActionSet{unknown: true}
		s.findings.widen(trust.Anomaly{Kind: Malformed, Construct: "Statement", Message: "the statement is " + describe(v) + ", not an object, so what it grants is not known", Source: src})
		return s
	}
	byName := map[string]*memberGroup{}
	groups := groupMembers(v, exactName)
	for i := range groups {
		g := &groups[i]
		if !statementMembers[g.name] {
			s.findings.widen(trust.Anomaly{Kind: trust.Unmodelled, Construct: g.name, Message: "the statement member " + strconv.QuoteToASCII(g.name) + " is not one this parser models, so what it does to the statement is not known", Source: src})
			continue
		}
		byName[g.name] = g
	}
	s.Sid = parseSid(byName["Sid"], src, &s.findings)
	s.Effect = parseEffect(byName["Effect"], src, &s.findings)
	s.Principals = parsePrincipals(byName["Principal"], byName["NotPrincipal"], src, &s.findings)
	s.Actions = parseActions(byName["Action"], byName["NotAction"], src, &s.findings)
	s.Conditions = parseConditions(byName["Condition"], src, &s.findings)
	return s
}

// parseSid takes the first Sid written when it is a string. A Sid names the
// statement for people; nothing about admission depends on it.
func parseSid(g *memberGroup, src string, f *findings) string {
	if g == nil {
		return ""
	}
	if len(g.values) > 1 {
		f.note(duplicated(*g, "", src))
	}
	v := g.values[0]
	if v.kind != kindString {
		f.note(trust.Anomaly{Kind: Malformed, Construct: "Sid", Message: "Sid is " + describe(v) + ", not a string", Source: src + ".Sid"})
		return ""
	}
	return v.text
}

// parseEffect accepts exactly "Allow" and "Deny". Anything else is
// EffectUnknown, which the evaluator reads as possibly Allow: reading a
// malformed effect as Deny would report the role as narrower than it is.
// The statement's set is still evaluated, so the anomaly is a note.
func parseEffect(g *memberGroup, src string, f *findings) trust.Effect {
	const consequence = "the effect is not known and is read as possibly Allow"
	switch {
	case g == nil:
		f.note(trust.Anomaly{Kind: Malformed, Construct: "Effect", Message: "the statement has no Effect member, so " + consequence, Source: src + ".Effect"})
		return trust.EffectUnknown
	case len(g.values) > 1:
		f.note(duplicated(*g, consequence, src))
		return trust.EffectUnknown
	}
	v := g.values[0]
	if v.kind != kindString {
		f.note(trust.Anomaly{Kind: Malformed, Construct: "Effect", Message: "Effect is " + describe(v) + ", not a string, so " + consequence, Source: src + ".Effect"})
		return trust.EffectUnknown
	}
	switch v.text {
	case "Allow":
		return trust.Allow
	case "Deny":
		return trust.Deny
	}
	f.note(trust.Anomaly{Kind: Malformed, Construct: "Effect", Message: "Effect is " + strconv.QuoteToASCII(v.text) + `; AWS accepts exactly "Allow" or "Deny", so ` + consequence, Source: src + ".Effect"})
	return trust.EffectUnknown
}

// ActionSet is the statement's Action element: the action patterns as
// written, lower-cased, each a glob under the same rules as StringLike. It
// is unknown when the element could not be read as patterns at all, which
// leaves every grant of the statement unevaluated.
type ActionSet struct {
	unknown  bool
	patterns []eval.StringSet
}

// covers reports whether any pattern matches any of the actions.
func (a ActionSet) covers(actions ...string) bool {
	for _, pattern := range a.patterns {
		for _, action := range actions {
			if pattern.Contains(action) {
				return true
			}
		}
	}
	return false
}

// parseActions reads Action, a string or a list of strings naming actions
// with * and ? anywhere in the name. NotAction is recorded and widens rather
// than computed: its complement over an open set of actions is not a thing
// this parser states, and that is a deliberate non-goal, not an oversight.
func parseActions(action, notAction *memberGroup, src string, f *findings) ActionSet {
	const unknownActions = "which actions the statement grants is not known"
	switch {
	case action != nil && notAction != nil:
		f.widen(trust.Anomaly{Kind: DuplicateKey, Construct: "Action", Message: "the statement has both Action and NotAction; the IAM grammar allows one, so " + unknownActions, Source: src})
		return ActionSet{unknown: true}
	case notAction != nil:
		if len(notAction.values) > 1 {
			f.widen(duplicated(*notAction, unknownActions, src))
		}
		f.widen(trust.Anomaly{Kind: trust.Unmodelled, Construct: "NotAction", Message: "NotAction grants every action but the ones listed; this parser does not compute that complement, so " + unknownActions, Source: src + ".Action"})
		return ActionSet{unknown: true}
	case action == nil:
		f.widen(trust.Anomaly{Kind: trust.Unmodelled, Construct: "Action", Message: "the statement has neither Action nor NotAction, so " + unknownActions, Source: src + ".Action"})
		return ActionSet{unknown: true}
	case len(action.values) > 1:
		f.widen(duplicated(*action, unknownActions, src))
		return ActionSet{unknown: true}
	}
	texts, bad, inList := leaves(action.values[0])
	switch {
	case bad != nil && inList:
		f.widen(trust.Anomaly{Kind: Malformed, Construct: "Action", Message: "Action lists " + describe(bad) + " where a string is expected, so " + unknownActions, Source: src + ".Action"})
		return ActionSet{unknown: true}
	case bad != nil:
		f.widen(trust.Anomaly{Kind: Malformed, Construct: "Action", Message: "Action is " + describe(bad) + " where a string or a list of strings is expected, so " + unknownActions, Source: src + ".Action"})
		return ActionSet{unknown: true}
	case len(texts) == 0:
		f.widen(trust.Anomaly{Kind: Malformed, Construct: "Action", Message: "Action lists no actions; the IAM grammar requires at least one, so " + unknownActions, Source: src + ".Action"})
		return ActionSet{unknown: true}
	}
	set := ActionSet{patterns: make([]eval.StringSet, len(texts))}
	for i, text := range texts {
		set.patterns[i] = eval.Glob(fold(text))
	}
	return set
}

// memberGroup is every copy of one object member, in document order: the
// name the copies share, each copy's spelling, and each copy's value. More
// than one value is a duplicate, the fact a decoder into a map erases.
type memberGroup struct {
	name      string
	spellings []string
	values    []*value
}

// groupMembers collects an object's members by name, in order of first
// appearance. canonical decides which spellings are one name: exactName for
// the grammar's elements, which are matched as written, foldWide for
// condition keys, which AWS matches without regard to case.
func groupMembers(v *value, canonical func(string) string) []memberGroup {
	var groups []memberGroup
	index := map[string]int{}
	for _, m := range v.members {
		name := canonical(m.name)
		i, seen := index[name]
		if !seen {
			i = len(groups)
			index[name] = i
			groups = append(groups, memberGroup{name: name})
		}
		groups[i].spellings = append(groups[i].spellings, m.name)
		groups[i].values = append(groups[i].values, m.value)
	}
	return groups
}

func exactName(name string) string { return name }

// duplicated is the anomaly for a statement member written more than once.
// consequence says what the parser does about it and finishes the sentence,
// or is empty when nothing changes.
func duplicated(g memberGroup, consequence, src string) trust.Anomaly {
	message := "the member " + g.name + " appears more than once in the statement"
	if consequence != "" {
		message += "; a JSON decoder keeps one and the deployed policy may carry either, so " + consequence
	}
	return trust.Anomaly{Kind: DuplicateKey, Construct: g.name, Message: message, Source: src}
}

// leaves reads a member that takes a string or a list of strings, the shape
// Action, every principal kind and every condition value share. bad is the
// first value that is not a string, with inList saying whether it sat
// inside a list, so that the sentence can say which shape was wrong.
func leaves(v *value) (texts []string, bad *value, inList bool) {
	switch v.kind {
	case kindString:
		return []string{v.text}, nil, false
	case kindArray:
		texts = make([]string, 0, len(v.items))
		for _, item := range v.items {
			if item.kind != kindString {
				return nil, item, true
			}
			texts = append(texts, item.text)
		}
		return texts, nil, false
	}
	return nil, v, false
}

// excerptRunes bounds what a sentence quotes of a value. The statement's Raw
// has the whole text; the sentence needs enough to recognise it.
const excerptRunes = 48

// describe names a value's JSON type and quotes its source, for a sentence
// that says what was met where something else was expected: "a number (5)".
// Whitespace between tokens collapses to one space and a long value is cut
// with an ellipsis, so the sentence stays one line.
func describe(v *value) string {
	return v.kind.String() + " (" + excerpt(v.bytes()) + ")"
}

// excerpt collapses the four JSON whitespace characters only. Any other
// space-like rune sits inside a string literal and is the customer's text.
// A rune outside printable ASCII is written as the escape strconv would
// give it, for the reason every quotation in a sentence uses QuoteToASCII:
// a lookalike letter prints identically to the one it resembles, and a
// sentence explaining why "Аllow" is not "Allow" has to show the
// difference. The walk stops as soon as the excerpt is full: a value can
// be megabytes long and is described once per grant.
func excerpt(raw []byte) string {
	var collapsed []byte
	pending := false
	runes := 0
	for _, r := range string(raw) {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			pending = true
			continue
		}
		if pending {
			collapsed = append(collapsed, ' ')
			pending = false
			runes++
		}
		if ' ' <= r && r <= '~' {
			collapsed = append(collapsed, byte(r))
		} else {
			quoted := strconv.QuoteRuneToASCII(r)
			collapsed = append(collapsed, quoted[1:len(quoted)-1]...)
		}
		runes++
		if runes > excerptRunes {
			return string(collapsed) + "..."
		}
	}
	return string(collapsed)
}
