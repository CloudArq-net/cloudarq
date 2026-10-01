package aws

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/parse/casefold"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// ConditionBlock is the statement's Condition element as written: one
// constraint per (operator block, key), in document order, duplicates
// included. It is evaluated once per principal, because which keys are a
// principal's own claims depends on the principal.
type ConditionBlock struct {
	constraints []constraint
}

// constraint is one key under one operator, with its value as written.
type constraint struct {
	operator string
	key      string
	value    *value
	repeated repeat
}

// repeat records that a constraint's key or its whole operator block was
// written more than once, or that its key and another are one key under a
// folding AWS may or may not apply: what repeated, for the Unknown's
// reason, and the sentence that widens the claim. Both are empty when
// nothing repeated.
type repeat struct {
	what    string // "key token.actions.githubusercontent.com:sub" or "operator StringEquals"
	message string
}

// parseConditions reads the Condition element into constraints. A block
// that is not an object leaves the statement unevaluated; a block with no
// keys is outside the grammar and leaves the set an upper bound, because
// what IAM makes of one is not documented and the other blocks' set is a
// superset of every reading.
func parseConditions(g *memberGroup, src string, f *findings) ConditionBlock {
	if g == nil {
		return ConditionBlock{}
	}
	if len(g.values) > 1 {
		f.widen(duplicated(*g, "what the conditions require is not known", src))
		return ConditionBlock{}
	}
	src += ".Condition"
	v := g.values[0]
	if v.kind != kindObject {
		f.widen(trust.Anomaly{Kind: Malformed, Construct: "Condition", Message: "Condition is " + describe(v) + ", not an object, so what it requires is not known", Source: src})
		return ConditionBlock{}
	}
	var block ConditionBlock
	for _, op := range groupMembers(v, exactName) {
		name := spellOperator(op.name)
		if len(op.values) > 1 {
			f.note(trust.Anomaly{Kind: DuplicateKey, Construct: op.name, Message: "the operator " + name + " appears more than once in the Condition; a JSON decoder keeps one block and the deployed policy may carry either", Source: src})
		}
		for _, blockValue := range op.values {
			if blockValue.kind != kindObject {
				f.widen(trust.Anomaly{Kind: Malformed, Construct: op.name, Message: "the operator block " + name + " is " + describe(blockValue) + ", not an object, so what it requires is not known", Source: src})
				continue
			}
			if len(blockValue.members) == 0 {
				f.doubt(trust.Anomaly{Kind: Malformed, Construct: op.name, Message: "the operator block " + name + " lists no keys; the IAM grammar requires at least one, so what it requires is not known", Source: src})
				continue
			}
			for _, key := range groupMembers(blockValue, casefold.Wide) {
				repeated := repeatOf(key, op.name, len(op.values) > 1)
				for j, kv := range key.values {
					block.constraints = append(block.constraints, constraint{operator: op.name, key: key.spellings[j], value: kv, repeated: repeated})
				}
			}
		}
	}
	return block
}

// repeatOf is what a key's group, under one operator block, repeats. A
// duplicated operator block widens every key in every copy: a decoder
// keeps one block, so any key in the other may be absent from the
// deployed policy, and absent is unconstrained. Spellings that are one
// key under ASCII case folding are one key written twice. Spellings that
// are one key only under a wider folding may be one key or two; no page
// says which, and reading them as two would meet their constraints in a
// set that can be provably empty, reported exact. A group can hold both,
// and the sentence then states the certain fact and the conditional one
// each with the spellings it is about, because a sentence calling the
// whole group a possible duplicate is false for the certain pair.
func repeatOf(key memberGroup, operator string, blockRepeated bool) repeat {
	name := spellOperator(operator)
	if blockRepeated {
		return repeat{"operator " + operator, "the operator " + name + " appears more than once in the Condition; a JSON decoder keeps one block and the deployed policy may carry either, so the claim is not constrained"}
	}
	if len(key.values) == 1 {
		return repeat{}
	}
	// The spellings by ASCII fold, in order of first appearance: each
	// fold is one key for certain, spoken of by its first spelling.
	var folds []string
	copies := map[string]int{}
	spelling := map[string]string{}
	for _, s := range key.spellings {
		f := fold(s)
		if copies[f] == 0 {
			folds = append(folds, f)
			spelling[f] = strconv.QuoteToASCII(s)
		}
		copies[f]++
	}
	var certain, every, certainFolds []string
	for _, f := range folds {
		every = append(every, spelling[f])
		if copies[f] > 1 {
			certain = append(certain, spelling[f])
			certainFolds = append(certainFolds, f)
		}
	}
	const wider = " are one key if AWS folds letters outside ASCII, which no page documents"
	const decoder = "; a JSON decoder keeps one and the deployed policy may carry either, so the claim is not constrained"
	switch {
	case len(folds) == 1:
		return repeat{"duplicate key " + folds[0], "the key " + certain[0] + " appears more than once under " + name + decoder}
	case len(certain) == 0:
		return repeat{"possible duplicate key " + folds[0], "the keys " + enumerate(every) + " under " + name + wider + "; a JSON decoder would then keep one and the deployed policy may carry either, so the claim is not constrained"}
	case len(certain) == 1:
		return repeat{"duplicate key " + certainFolds[0], "the key " + certain[0] + " appears more than once under " + name + "; " + enumerate(every) + wider + decoder}
	}
	return repeat{"duplicate key " + certainFolds[0], "the keys " + enumerate(certain) + " each appear more than once under " + name + "; " + enumerate(every) + wider + decoder}
}

// enumerate renders two or more items for a sentence: "a and b", "a, b and c".
func enumerate(items []string) string {
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

// project evaluates the block in one principal's claim space: one Term,
// starting from the principal's own identity, every constraint met with
// the others on its claim, and for every fact that kept a constraint from
// being evaluated a caveat on its claim and an anomaly saying why. The
// identity goes into the same Term rather than being met afterwards, so
// that an Unknown beside it survives normalisation and renders as such;
// a Term of Unknowns alone collapses to everything before any Meet. The
// effect is what the sentences are written for: a condition that passes
// on an absent key restricts nothing in an Allow and denies more than it
// reads in a Deny.
func (b ConditionBlock) project(p principal, effect trust.Effect, vocabulary ClaimVocabulary, variables variableMode, src string) (eval.AdmittedSet, []trust.Anomaly) {
	term := p.identity()
	var caveats []eval.Caveat
	var anomalies []trust.Anomaly
	for _, c := range b.constraints {
		o := c.evaluate(p, effect, vocabulary, variables, src)
		if existing, ok := term[o.claim]; ok {
			term[o.claim] = existing.Meet(o.set)
		} else {
			term[o.claim] = o.set
		}
		for _, a := range o.anomalies {
			anomalies = append(anomalies, a)
			caveats = append(caveats, eval.Caveat{Claim: o.claim, Reason: a.Message, Source: src})
		}
		anomalies = append(anomalies, o.notes...)
	}
	return withCaveats(eval.NewAdmittedSet(term), caveats), anomalies
}

// outcome is one constraint evaluated for one principal. Every fact that
// kept it from being evaluated is an anomaly, and one is enough to make
// the set Unknown; the facts are independent, so a vacuous operator on a
// key that could not be placed is reported as both. Notes are facts that
// change nothing about the set and are worth a sentence all the same.
type outcome struct {
	claim     trust.ClaimKey
	set       eval.StringSet
	anomalies []trust.Anomaly
	notes     []trust.Anomaly
}

// keyScope is how a principal reads a condition key.
type keyScope int

const (
	ownClaim        keyScope = iota // prefixed by the principal's own provider: a claim of its token
	identityClaim                   // an AWS principal key on an AWS principal: a claim of the pseudo-issuer
	requestContext                  // an AWS service's key: it describes the request, not the identity
	foreignKey                      // another provider's key: kept as written, no token of this issuer carries it
	unknownProvider                 // a provider's key under the anonymous principal: which provider is not known
	noPrefix                        // no colon at all: not the shape of a context key
	notAName                        // the claim part is not a claim name
)

// identityKeys are the AWS principal keys that describe who the caller is,
// lower-cased. Any other service key describes the request.
var identityKeys = map[string]bool{
	"aws:principalarn":     true,
	"aws:principalaccount": true,
	"aws:principalorgid":   true,
	"aws:principaltype":    true,
	"sts:externalid":       true,
}

// scope says how the principal reads key, and which claim it names. The
// claim is the folded key, except for the principal's own claims, whose
// name is the part after the provider identifier and the colon.
//
// A prefix that is an identity provider's is a host, which has a dot; an
// AWS service's prefix, aws, sts, iam, saml, ec2, never does. The dot is
// what tells a provider's key, which a token of another provider cannot
// carry, from a service's, which describes the request or the role and
// which this parser does not evaluate. Mistaking a provider's key for a
// service's widens; the reverse put an exact constraint on a claim no
// token carries and rejected every token AWS admits.
func (p principal) scope(key string) (trust.ClaimKey, keyScope) {
	folded := fold(key)
	if claim, own := p.ownClaim(key); own {
		if _, ok := trust.Claim(claim); !ok {
			return trust.ClaimKey(folded), notAName
		}
		return trust.ClaimKey(claim), ownClaim
	}
	switch {
	case !strings.Contains(folded, ":"):
		return trust.ClaimKey(folded), noPrefix
	case IsServiceKey(trust.ClaimKey(folded)):
		if p.awsIdentity() && identityKeys[folded] {
			return trust.ClaimKey(folded), identityClaim
		}
		return trust.ClaimKey(folded), requestContext
	case p.kind == principalAnyone || p.kind == principalAnyIssuer:
		return trust.ClaimKey(folded), unknownProvider
	}
	return trust.ClaimKey(folded), foreignKey
}

// IsServiceKey reports whether key, as this parser files a condition key,
// is one an AWS service fills rather than a claim of a provider's token:
// its prefix before the colon has no dot, where a provider's is a host.
// Beside the principal keys of an AWS principal, such a key describes the
// request, and this parser does not evaluate it.
func IsServiceKey(key trust.ClaimKey) bool {
	prefix, _, hasColon := strings.Cut(string(key), ":")
	return hasColon && !strings.Contains(prefix, ".")
}

// MayName reports whether a caveat this parser filed under key may stand
// for a constraint on claim of issuer's tokens. A key whose name is not
// known is filed under its name as written: a letter outside ASCII with case
// variants, in the claim or in the provider before it, may be the letter
// AWS reads there, and a policy variable in a key may become any key. The
// caveat says only that a constraint went unread, and a reader asking which
// claim it was on needs the parser's rules for keys, which are these: the
// key is the claim, or spells it under the widest folding AWS could apply,
// or is issuer's own key for it spelled so.
func MayName(key trust.ClaimKey, issuer trust.IssuerRef, claim trust.ClaimKey) bool {
	k := string(key)
	if _, variable := variableReference(k); variable {
		return true
	}
	// A key with no letter beyond ASCII that has case variants names what
	// it spells, case aside, the folding AWS documents, and folding it is
	// free where the widest folding allocates for every letter; a placement
	// asks this of every caveat.
	canon := fold
	if foldsBeyondASCII(k) {
		canon = casefold.Wide
	}
	wanted := canon(string(claim))
	if canon(k) == wanted {
		return true
	}
	provider := canon(strings.TrimSuffix(strings.TrimPrefix(string(issuer), "https://"), "/"))
	for i := 0; i < len(k); i++ {
		if k[i] == ':' && canon(strings.TrimSuffix(k[:i], "/")) == provider && canon(k[i+1:]) == wanted {
			return true
		}
	}
	return false
}

// evaluate decides what one constraint means for one principal. The key,
// the operator and the values are each read on their own, so that every
// fact is stated: a ForAllValues still passes on an absent key whatever
// the key is, and an operator this parser does not model is named even
// when the key beside it has a story of its own. Any fact makes the claim
// Unknown, with every fact as its reason.
func (c constraint) evaluate(p principal, effect trust.Effect, vocabulary ClaimVocabulary, variables variableMode, src string) outcome {
	claim, scope := p.scope(c.key)
	quotedKey := strconv.QuoteToASCII(c.key)
	var facts []fact
	var notes []trust.Anomaly
	if c.repeated.message != "" {
		facts = append(facts, fact{c.repeated.what, DuplicateKey, c.operator, c.repeated.message})
	}
	// keyNotKnown is set by a fact that says which key this is is not
	// known: whether AWS documents it is then not known either. values is
	// how the vocabulary read the key, which says whether it may hold
	// several values.
	keyNotKnown, values := false, ClaimRead
	if foldsBeyondASCII(c.key) {
		keyNotKnown = true
		facts = append(facts, fact{"folding of " + c.key, trust.Unmodelled, c.key, "the condition key " + quotedKey + " holds a letter outside ASCII with case variants of its own; AWS documents no folding for it, so which key it names is not known and the claim is not constrained"})
	}
	if scope != ownClaim && p.mayOwn(c.key) {
		keyNotKnown = true
		facts = append(facts, fact{"folding of provider " + p.identifier, trust.Unmodelled, c.key, "the condition key " + quotedKey + " is a claim of the Federated principal " + strconv.QuoteToASCII(p.text) + " if AWS folds letters outside ASCII, which no page documents, so which key it names is not known and the claim is not constrained"})
	}
	if reference, ok := variableReference(c.key); ok {
		if variables == variablesLiteral {
			notes = append(notes, trust.Anomaly{Kind: VariableIsLiteral, Claim: claim, Construct: reference, Message: "the condition key " + quotedKey + " holds " + strconv.QuoteToASCII(reference) + ", which is literal text because this document's Version does not resolve policy variables; if a variable was meant, the condition does not do what it looks like it does", Source: src})
		} else {
			keyNotKnown = true
			facts = append(facts, fact{reference, trust.Unmodelled, reference, "the condition key " + quotedKey + " holds the policy variable " + reference + "; AWS documents variables in condition values and the Resource element, not in keys, so which key it names is not known and the claim is not constrained"})
		}
	}
	switch scope {
	case notAName:
		facts = append(facts, fact{string(claim), Malformed, c.key, "the condition key " + quotedKey + " names no claim, so the claim is not constrained"})
	case noPrefix:
		facts = append(facts, fact{string(claim), Malformed, c.key, "the condition key " + quotedKey + " has no provider prefix, so which request value it names is not known and the claim is not constrained"})
	case requestContext:
		facts = append(facts, fact{string(claim), trust.Unmodelled, c.key, "the condition key " + quotedKey + " is a fact about the request, not a claim of the token, so this parser does not evaluate it and the claim is not constrained"})
	case unknownProvider:
		facts = append(facts, fact{string(claim), trust.Unmodelled, c.key, "the condition key " + quotedKey + " is a claim of a provider this statement does not name; with every principal admitted, which provider populates it is not known, so the claim is not constrained"})
	case ownClaim:
		// Which keys AWS fills for the issuer's tokens, and from which
		// claim, the vocabulary knows and this parser does not: a guessed
		// key could be one AWS never fills, and a constraint on it would
		// reject every token.
		name, reading := trust.ClaimKey(""), IssuerNotKnown
		if vocabulary != nil {
			name, reading = vocabulary(p.issuer, string(claim))
		}
		switch reading {
		case ClaimRead, MultivaluedRead, MultiValuedClaimRead:
			claim, values = name, reading
		case KeyNotDocumented:
			if !keyNotKnown {
				facts = append(facts, fact{"key not documented", trust.Unmodelled, c.key, "the condition key " + quotedKey + " is not one AWS documents for the tokens of " + strconv.QuoteToASCII(string(p.issuer)) + ", so whether a request carries it is not known and the claim is not constrained"})
			}
		default:
			facts = append(facts, fact{"vocabulary of " + string(p.issuer) + " unknown", trust.Unmodelled, c.key, "the claim vocabulary of " + strconv.QuoteToASCII(string(p.issuer)) + " is not known to this parser, so the spelling " + strconv.QuoteToASCII(string(claim)) + " of the condition key " + quotedKey + " cannot be reconciled with the token's and the claim is not constrained"})
		}
	}
	op := parseOperator(c.operator)
	on := spellOperator(c.operator) + " on " + spellClaim(claim)
	vacuous := on + " passes when the claim is absent, so it does not restrict what it looks like it restricts"
	switch {
	case effect == trust.Deny && op.negated:
		// The value a negated Deny names is the one token it does not deny.
		vacuous = on + " passes when the claim is absent, so this Deny denies tokens without the claim as well as every token whose claim does not match the values it names"
	case effect == trust.Deny:
		vacuous = on + " passes when the claim is absent, so this Deny denies tokens without the claim as well as the ones it names"
	}
	switch {
	case !op.recognised:
		facts = append(facts, fact{c.operator, trust.Unmodelled, c.operator, "operator " + on + " is not modelled by this parser, so the claim is not constrained"})
	case op.setPrefix == "ForAllValues", op.ifExists:
		facts = append(facts, fact{c.operator, trust.Unmodelled, c.operator, vacuous})
	case op.setPrefix == "ForAnyValue":
		facts = append(facts, fact{c.operator, trust.Unmodelled, c.operator, on + " compares a set of request values, which this parser does not model, so the claim is not constrained"})
	case op.base == "Null":
		facts = append(facts, fact{c.operator, trust.Unmodelled, c.operator, c.nullMessage(on)})
	case op.base == "StringNotEquals", op.base == "StringNotLike", op.base == "StringNotEqualsIgnoreCase":
		facts = append(facts, fact{c.operator, trust.Unmodelled, c.operator, on + " admits every value but the ones listed and passes when the claim is absent; this parser does not model complements, so the claim is not constrained"})
	case op.base == "StringEqualsIgnoreCase":
		facts = append(facts, fact{c.operator, trust.Unmodelled, c.operator, on + " matches the value in any casing, which this parser cannot express, so the claim is not constrained"})
	case op.base != "StringEquals" && op.base != "StringLike":
		facts = append(facts, fact{c.operator, trust.Unmodelled, c.operator, "operator " + on + " is not modelled by this parser, so the claim is not constrained"})
	}
	// A request may carry several values for a key that may hold them, and a
	// constraint that compared one would narrow the set on a guess: no one
	// value meets both StringEquals "authenticated" and StringLike
	// "graph.facebook.com", and a Facebook user's amr carries both values;
	// none meets both StringEquals "sts.amazonaws.com" and StringLike
	// "vault*" on aud, and a Kubernetes service account token may carry both
	// audiences. The fact stands beside whatever else is said of the
	// operator, so that modelling that operator one day cannot make the key
	// exact. Null reads only whether the key is present, and AWS pairs it
	// with set operators on a multivalued key in its own examples.
	if values != ClaimRead && op.setPrefix == "" && op.base != "Null" {
		facts = append(facts, c.severalValues(values, on, p.issuer))
	}
	modelled := len(facts) == 0
	var set eval.StringSet = eval.None()
	texts, bad, inList := leaves(c.value)
	switch {
	case bad != nil && op.base == "Null":
		// Null reads its own value and has said what it found.
	case bad != nil && inList:
		facts = append(facts, fact{c.operator, Malformed, c.operator, on + " lists " + describe(bad) + " where a string is expected, so the claim is not constrained"})
	case bad != nil:
		facts = append(facts, fact{c.operator, Malformed, c.operator, on + " has a value that is " + describe(bad) + " where a string or a list of strings is expected, so the claim is not constrained"})
	case len(texts) == 0:
		facts = append(facts, fact{c.operator, trust.Unmodelled, c.operator, on + " lists no values; AWS documents no meaning for an empty list, so the claim is not constrained"})
	case modelled:
		var valueFacts []fact
		var valueNotes []trust.Anomaly
		set, valueFacts, valueNotes = c.valueSet(texts, claim, op.base == "StringLike", variables, src)
		facts = append(facts, valueFacts...)
		notes = append(notes, valueNotes...)
	}
	o := outcome{claim: claim, set: set, notes: notes}
	if len(facts) == 0 {
		return o
	}
	unknowns := make([]eval.StringSet, len(facts))
	for i, f := range facts {
		o.anomalies = append(o.anomalies, trust.Anomaly{Kind: f.kind, Claim: claim, Construct: f.construct, Message: f.message, Source: src})
		unknowns[i] = eval.Unknown(f.reason)
	}
	o.set = joinAll(unknowns, eval.StringSet.Join)
	return o
}

// severalValues is the fact that keeps a condition without a set prefix on
// a key that may hold several values from being evaluated, in the words of
// why it may: AWS's sentence about the key, or the census's about the claim
// of the issuer's tokens AWS reads it from.
func (c constraint) severalValues(values KeyReading, on string, issuer trust.IssuerRef) fact {
	quotedKey := strconv.QuoteToASCII(c.key)
	if values == MultivaluedRead {
		return fact{"multivalued key", trust.Unmodelled, c.key, on + " has no set prefix, and AWS documents the condition key " + quotedKey + " as multivalued, which a policy tests with condition set operators; what an operator without one does on such a key AWS does not document, so the claim is not constrained"}
	}
	return fact{"multi-valued claim", trust.Unmodelled, c.key, on + " has no set prefix, and a token of " + strconv.QuoteToASCII(string(issuer)) + " may carry several values in the claim AWS reads the condition key " + quotedKey + " from; how many of them AWS compares, and what an operator without a set prefix does on them, AWS does not document, so the claim is not constrained"}
}

// fact is one reason a constraint could not be evaluated: the Unknown's
// reason, and the anomaly's kind, construct and sentence.
type fact struct {
	reason, kind, construct, message string
}

// valueSet is the set a StringEquals or StringLike lists: the union of its
// values, or the facts that keep it from being one, and a note for every
// value AWS reads as literal text where a variable may have been meant. A
// pattern that admits every string is a presence test, StringLike passing
// only when the key is present; eval.Glob turns such a pattern into Any
// and a Term drops an Any-valued claim, which would read "present, any
// value" as "absent passes". Presence is not a set of values, so that
// value is Unknown.
func (c constraint) valueSet(texts []string, claim trust.ClaimKey, like bool, variables variableMode, src string) (eval.StringSet, []fact, []trust.Anomaly) {
	sets := make([]eval.StringSet, 0, len(texts))
	var notes []trust.Anomaly
	for _, text := range texts {
		literal, problem := resolveVariables(text, variables, like)
		if problem.construct != "" {
			return nil, []fact{{problem.construct, trust.Unmodelled, problem.construct, "the value " + strconv.QuoteToASCII(text) + " on " + spellClaim(claim) + " " + problem.message}}, nil
		}
		if reference, ok := variableReference(text); ok && variables == variablesLiteral {
			notes = append(notes, trust.Anomaly{Kind: VariableIsLiteral, Claim: claim, Construct: reference, Message: "the value " + strconv.QuoteToASCII(text) + " on " + spellClaim(claim) + " holds " + strconv.QuoteToASCII(reference) + ", which is literal text because this document's Version does not resolve policy variables; if a variable was meant, the condition does not do what it looks like it does", Source: src})
		}
		if like {
			sets = append(sets, eval.Glob(literal))
		} else {
			sets = append(sets, eval.Exact(literal))
		}
	}
	set := joinAll(sets, eval.StringSet.Join)
	if set.IsTop() {
		return nil, []fact{{c.operator, trust.Unmodelled, c.operator, spellOperator(c.operator) + " on " + spellClaim(claim) + " matches every value but only when the claim is present, which this parser cannot express, so the claim is not constrained"}}, notes
	}
	return set, nil, notes
}

// nullMessage says which way a Null condition reads. AWS documents the
// value as the JSON string "true" or "false"; a JSON boolean is read here
// the same way, so nothing rests on whether AWS accepts one. A one-element list holds its element's polarity.
func (c constraint) nullMessage(on string) string {
	v := c.value
	if v.kind == kindArray && len(v.items) == 1 {
		v = v.items[0]
	}
	polarity := ""
	switch v.kind {
	case kindBool:
		polarity = strconv.FormatBool(v.boolean)
	case kindString:
		polarity = v.text
	}
	switch polarity {
	case "true":
		return on + ` is "true": the claim must be absent, which this parser cannot express, so the claim is not constrained`
	case "false":
		return on + ` is "false": the claim must be present, which this parser cannot express, so the claim is not constrained`
	}
	return on + " has the value " + quoteOrDescribe(c.value) + `, which is neither "true" nor "false", so the claim is not constrained`
}

// quoteOrDescribe quotes a string value and describes any other, for a
// sentence about the value AWS would compare.
func quoteOrDescribe(v *value) string {
	if v.kind == kindString {
		return strconv.QuoteToASCII(v.text)
	}
	return describe(v)
}

// spellOperator is how a sentence names an operator: one AWS documents is
// spelled as AWS spells it, and any other spelling is quoted, so that an
// empty or a lookalike name is visible rather than a blank.
func spellOperator(text string) string {
	if parseOperator(text).recognised {
		return text
	}
	return strconv.QuoteToASCII(text)
}

// spellClaim is how a sentence names a claim: bare when it is printable
// ASCII with no space, quoted otherwise, for the same reason.
func spellClaim(claim trust.ClaimKey) string {
	for _, r := range claim {
		if r <= ' ' || r > '~' {
			return strconv.QuoteToASCII(string(claim))
		}
	}
	return string(claim)
}

// operator is a condition operator name taken apart: at most one set
// prefix, the IfExists suffix, and between them a base operator AWS
// documents, each exactly as AWS spells it. Any other spelling is not an
// operator at all, and the sentences that assert what an operator does on
// an absent key are owed only to one that exists. A negated operator,
// StringNotEquals, ArnNotLike, NotIpAddress, matches every value but the
// ones listed; the documented operators spell that with Not and no other
// documented operator holds the word.
type operator struct {
	recognised bool
	setPrefix  string
	base       string
	ifExists   bool
	negated    bool
}

// documentedOperators are the condition operators the operators page
// lists. The suffix goes on any of them but Null, which the page says
// takes none.
var documentedOperators = map[string]bool{
	"StringEquals": true, "StringNotEquals": true, "StringEqualsIgnoreCase": true, "StringNotEqualsIgnoreCase": true, "StringLike": true, "StringNotLike": true,
	"NumericEquals": true, "NumericNotEquals": true, "NumericLessThan": true, "NumericLessThanEquals": true, "NumericGreaterThan": true, "NumericGreaterThanEquals": true,
	"DateEquals": true, "DateNotEquals": true, "DateLessThan": true, "DateLessThanEquals": true, "DateGreaterThan": true, "DateGreaterThanEquals": true,
	"Bool": true, "BinaryEquals": true, "IpAddress": true, "NotIpAddress": true,
	"ArnEquals": true, "ArnLike": true, "ArnNotEquals": true, "ArnNotLike": true,
	"Null": true,
}

func parseOperator(text string) operator {
	var op operator
	for _, prefix := range []string{"ForAllValues", "ForAnyValue"} {
		if strings.HasPrefix(text, prefix+":") {
			op.setPrefix = prefix
			text = strings.TrimPrefix(text, prefix+":")
			break
		}
	}
	if strings.HasSuffix(text, "IfExists") {
		op.ifExists = true
		text = strings.TrimSuffix(text, "IfExists")
	}
	op.base = text
	op.recognised = documentedOperators[text] && !(op.ifExists && text == "Null")
	op.negated = op.recognised && strings.Contains(text, "Not")
	return op
}

// variableProblem is why a value holding "${" could not be read as a
// literal: construct names what was met, message finishes the sentence.
type variableProblem struct {
	construct string
	message   string
}

// resolveVariables turns a value into the literal AWS compares, or says
// why it cannot. Under the 2012 language the predefined ${*}, ${?} and ${$}
// stand for the characters they name; under StringLike a literal * or ?
// is a character eval.Glob cannot express, so that value is Unknown. Any
// other reference is a policy variable, resolved per request.
func resolveVariables(text string, variables variableMode, like bool) (string, variableProblem) {
	if !strings.Contains(text, "${") {
		return text, variableProblem{}
	}
	switch variables {
	case variablesLiteral:
		return text, variableProblem{}
	case variablesUncertain:
		return "", variableProblem{"${", `holds "${", and whether this document's Version reads it as a policy variable is not known, so the claim is not constrained`}
	}
	var b strings.Builder
	rest := text
	for {
		i := strings.Index(rest, "${")
		if i < 0 {
			b.WriteString(rest)
			return b.String(), variableProblem{}
		}
		b.WriteString(rest[:i])
		rest = rest[i:]
		j := strings.Index(rest, "}")
		if j < 0 {
			return "", variableProblem{"${", `holds an unterminated "${", which this parser cannot read, so the claim is not constrained`}
		}
		reference := rest[:j+1]
		rest = rest[j+1:]
		switch reference {
		case "${*}", "${?}":
			if like {
				return "", variableProblem{reference, "holds the escaped wildcard " + reference + " under StringLike, which this parser cannot express, so the claim is not constrained"}
			}
			b.WriteByte(reference[2])
		case "${$}":
			b.WriteByte('$')
		default:
			return "", variableProblem{reference, "holds the policy variable " + reference + ", which is resolved per request, so the claim is not constrained"}
		}
	}
}

// fold lower-cases ASCII letters and nothing else. It is the folding AWS
// documents for context key names by example, aws:SourceIP for
// AWS:SourceIp, and the one this parser applies to keys and to action
// names. strings.ToLower would also fold U+212A KELVIN SIGN onto k, and a
// key is handed to the vocabulary as nearly as written.
func fold(s string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, s)
}

// foldsBeyondASCII reports whether s holds a letter outside ASCII with
// case variants of its own: a long s, a Kelvin sign, an umlaut, a dotless
// i, a ligature. Whether AWS folds such a letter onto another spelling is
// not documented, and a parser that folded it would claim AWS does while
// one that did not would claim AWS does not; either guess is the narrow
// direction on one of two documents that differ by that letter. A key
// holding one is Unknown.
func foldsBeyondASCII(s string) bool { return strings.ContainsFunc(s, foldableBeyondASCII) }

// foldableBeyondASCII reports whether r is the letter foldsBeyondASCII
// looks for: outside ASCII, with case variants of its own. Which letters
// have them is read from the engine's own case folding tables, never from
// the toolchain's, whose Unicode version moves with the compiler.
func foldableBeyondASCII(r rune) bool { return r >= utf8.RuneSelf && casefold.HasVariants(r) }

// joinAll folds items with join as a balanced tree. Join renormalises its
// result, so a left fold over n values renormalises n lists of growing
// length, cubic for a union of Exacts: 4,000 values took over a minute.
// The balanced fold renormalises each value about log n times, and the
// result is the same, because Join is associative and commutative and
// the normal form is canonical. items must not be empty.
func joinAll[T any](items []T, join func(T, T) T) T {
	for len(items) > 1 {
		merged := make([]T, 0, (len(items)+1)/2)
		for i := 0; i < len(items); i += 2 {
			if i+1 < len(items) {
				merged = append(merged, join(items[i], items[i+1]))
			} else {
				merged = append(merged, items[i])
			}
		}
		items = merged
	}
	return items[0]
}

// withCaveats declares every caveat on the set. WithCaveat re-sorts the
// set's list on each call, so a loop over the caveats of a block with
// thousands of unevaluated keys is quadratic in the block; the caveats
// are carried on empty sets and joined as a balanced tree instead.
func withCaveats(s eval.AdmittedSet, caveats []eval.Caveat) eval.AdmittedSet {
	if len(caveats) == 0 {
		return s
	}
	carriers := make([]eval.AdmittedSet, len(caveats))
	for i, c := range caveats {
		carriers[i] = eval.Nothing().WithCaveat(c)
	}
	return s.Join(joinAll(carriers, eval.AdmittedSet.Join))
}
