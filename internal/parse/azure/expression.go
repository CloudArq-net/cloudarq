package azure

import (
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// The flexible federated identity credential expression language, as
// Microsoft documents it at
// https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials
// (ms.date 2026-08-14, preview): an expression is clauses joined by " and ",
// a clause is claims['<name>'], one space, an operator, one space, and a
// comparand in single quotes; the operators are eq and matches, and matches
// takes * for any run of characters and ? for exactly one. The page says
// nothing about whitespace beyond "a single space", nothing about case, and
// only that "single quotes are interpreted as escape characters". Everything
// it does not say is read strictly: a construct outside the documented form
// leaves its claim Unknown rather than a guessed set.

// expressionSource is where every fact about the expression is located.
const expressionSource = "claimsMatchingExpression.value"

// clauseCap bounds the clauses read from one expression. Microsoft
// documents at most four claims for any issuer and no way to constrain one
// twice, so no documented expression comes near it; past it nothing the
// expression says is read, and sub is Unknown with the fact stated, never
// a truncated conjunction, which would under-approximate. The bound is
// what keeps the parser linear: eval attaches caveats one at a time,
// sorting the list on each, and an expression records one per clause it
// cannot model.
const clauseCap = 256

// clause is one comparison as written: claims['<name>'] <operator> '<comparand>'.
type clause struct {
	text      string // the clause as written, for quoting back
	name      string // inside claims['…'], as written
	operator  string
	comparand string // between the quotes, escapes as written
}

// splitClauses cuts an expression at every " and " outside single quotes.
// The quotes are scanned first, so a subject that contains the word is one
// clause, and a doubled quote stays inside its comparand. Empty pieces are
// kept so that the grammar can refuse them.
func splitClauses(expression string) []string {
	var out []string
	start, quoted := 0, false
	for i := 0; i < len(expression); i++ {
		switch {
		case expression[i] == '\'':
			if quoted && i+1 < len(expression) && expression[i+1] == '\'' {
				i++
				continue
			}
			quoted = !quoted
		case !quoted && strings.HasPrefix(expression[i:], " and "):
			out = append(out, expression[start:i])
			i += len(" and ") - 1
			start = i + 1
		}
	}
	return append(out, expression[start:])
}

// parseClause reads one clause under the documented grammar and refuses
// anything else: a second space, a tab, double quotes, a bare comparand,
// text after the closing quote. Whether the operator means anything is not
// the grammar's question; any word in that position parses, so that an
// operator Microsoft has not documented is reported by name.
func parseClause(text string) (clause, bool) {
	rest, ok := strings.CutPrefix(text, "claims['")
	if !ok {
		return clause{}, false
	}
	name, rest, ok := strings.Cut(rest, "'")
	if !ok {
		return clause{}, false
	}
	if _, ok := trust.Claim(name); !ok {
		return clause{}, false
	}
	rest, ok = strings.CutPrefix(rest, "] ")
	if !ok {
		return clause{}, false
	}
	end := 0
	for end < len(rest) && isASCIILetter(rest[end]) {
		end++
	}
	operator, rest := rest[:end], rest[end:]
	rest, ok = strings.CutPrefix(rest, " '")
	if operator == "" || !ok {
		return clause{}, false
	}
	comparand, rest, ok := scanComparand(rest)
	if !ok || rest != "" {
		return clause{}, false
	}
	return clause{text: text, name: name, operator: operator, comparand: comparand}, true
}

func isASCIILetter(b byte) bool {
	return ('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z')
}

// scanComparand reads up to the closing quote of a comparand whose opening
// quote is already consumed. A doubled quote is kept as written and does not
// close the comparand, the one reading under which Microsoft's escape
// sentence and its "single quotes" example both hold; what the pair means is
// decided by evaluate, not here.
func scanComparand(s string) (comparand, rest string, ok bool) {
	for i := 0; i < len(s); i++ {
		if s[i] != '\'' {
			continue
		}
		if i+1 < len(s) && s[i+1] == '\'' {
			i++
			continue
		}
		return s[:i], s[i+1:], true
	}
	return "", "", false
}

// operatorsByClaim is what Microsoft lists for one issuer: each claim an
// expression may name, and the operators it may use on it.
type operatorsByClaim map[trust.ClaimKey][]string

// language is what Microsoft documents of the expression language for one
// issuer: the claims an expression may name with the operators each takes,
// and the claims it must name, as groups of which one member must appear.
type language struct {
	operators operatorsByClaim
	required  [][]trust.ClaimKey
}

var (
	eqAndMatches   = []string{"eq", "matches"}
	eqOnly         = []string{"eq"}
	githubLanguage = language{
		operators: operatorsByClaim{
			"sub":                 eqAndMatches,
			"job_workflow_ref":    eqAndMatches,
			"repository_id":       eqOnly,
			"repository_owner_id": eqOnly,
		},
		required: [][]trust.ClaimKey{{"sub"}, {"repository_id", "repository_owner_id"}},
	}
	subOnly = language{operators: operatorsByClaim{"sub": eqAndMatches}}
)

// documentedLanguage is the "Issuer URLs, supported claims, and operators
// by platform" section of the page cited above, as of 2026-08-14: GitHub
// with sub, job_workflow_ref, repository_id and repository_owner_id, of
// which "a flexible federated identity credential must match the sub claim
// and one or both of" repository_id and repository_owner_id; GitLab and
// Terraform Cloud with sub alone and nothing said about what must appear.
// It is Microsoft's knowledge about Entra, not the issuer's about its
// tokens, which is why it sits here and not in the registry; when the
// registry gains an Azure section it moves there as data. An issuer
// outside the section has no documented behaviour at all, and the second
// result says so.
func documentedLanguage(issuer trust.IssuerRef) (language, bool) {
	switch {
	case issuer == "https://token.actions.githubusercontent.com":
		return githubLanguage, true
	case issuer == "https://app.terraform.io", issuer == "https://app.eu.terraform.io":
		return subOnly, true
	case isGitLabIssuer(issuer):
		return subOnly, true
	}
	return language{}, false
}

// spellClaims renders a group of claims for a sentence: "repository_id or
// repository_owner_id".
func spellClaims(claims []trust.ClaimKey) string {
	names := make([]string, len(claims))
	for i, c := range claims {
		names[i] = string(c)
	}
	return strings.Join(names, " or ")
}

// isGitLabIssuer matches the forms the page lists: https://gitlab.com, and
// https://gitlab.example.com or https://gitlab.example.ca "where example can
// be any string".
func isGitLabIssuer(issuer trust.IssuerRef) bool {
	host, ok := strings.CutPrefix(string(issuer), "https://gitlab.")
	if !ok || strings.Contains(host, "/") {
		return false
	}
	if host == "com" {
		return true
	}
	for _, tld := range []string{".com", ".ca"} {
		if middle, ok := strings.CutSuffix(host, tld); ok && middle != "" {
			return true
		}
	}
	return false
}

// evaluate reads an expression under an issuer into one Term. A clause the
// language models becomes an Exact or a Glob; a clause it does not leaves
// its claim Unknown with a caveat; and an expression outside the language,
// because a piece is outside the grammar or because it lacks a clause
// Microsoft says it must have, leaves sub Unknown and nothing else, since
// what was not understood may have governed every clause, and every
// documented expression must match sub.
func (r *reading) evaluate(expression string, issuer trust.IssuerRef) eval.Term {
	if strings.Count(expression, "'")%2 == 1 {
		return r.unbalanced()
	}
	pieces := splitClauses(expression)
	if len(pieces) > clauseCap {
		return r.tooManyClauses(len(pieces))
	}
	clauses := make([]clause, 0, len(pieces))
	var broken []string
	for _, text := range pieces {
		c, ok := parseClause(text)
		if !ok {
			broken = append(broken, text)
			continue
		}
		clauses = append(clauses, c)
	}
	if len(broken) != 0 {
		return r.unparseable(expression, broken)
	}
	lang, documented := documentedLanguage(issuer)
	keys := make([]trust.ClaimKey, len(clauses))
	count := map[trust.ClaimKey]int{}
	for i, c := range clauses {
		keys[i] = r.claimKey(c.name, lang)
		count[keys[i]]++
	}
	term := eval.Term{}
	for i, c := range clauses {
		key := keys[i]
		set := r.constraint(c, key, lang, documented, issuer)
		if count[key] > 1 {
			if _, seen := term[key]; !seen {
				r.doubt(trust.Anomaly{
					Kind:      trust.Unmodelled,
					Claim:     key,
					Construct: "repeated claim",
					Message:   claimLookup(string(key)) + " is constrained by " + strconv.Itoa(count[key]) + " clauses; Microsoft documents \"and\" for combining expressions against different claims and does not say what a repeated claim means",
					Source:    expressionSource,
				})
			}
			set = eval.Unknown("repeated claim")
		}
		term[key] = set
	}
	return r.required(term, keys, lang, issuer)
}

// required applies what Microsoft says an expression for the issuer must
// name. An expression missing a required clause is outside the documented
// language: whether Entra refuses it, applies it as written or applies
// nothing of it is not stated, and only the last reading is wider than the
// clauses say, so nothing they say survives and sub carries the Unknown.
// The facts recorded about the clauses stand, so that a reader sees why a
// claim that looks present is not the one required.
func (r *reading) required(term eval.Term, keys []trust.ClaimKey, lang language, issuer trust.IssuerRef) eval.Term {
	missing := false
	for _, group := range lang.required {
		if slices.ContainsFunc(group, func(k trust.ClaimKey) bool { return slices.Contains(keys, k) }) {
			continue
		}
		which := "it"
		if len(group) > 1 {
			which = "one of them"
		}
		r.doubt(trust.Anomaly{
			Kind:      trust.Unmodelled,
			Claim:     "sub",
			Construct: "missing required claim",
			Message:   "the expression names no clause on " + spellClaims(group) + "; Microsoft says a flexible federated identity credential for issuer " + quote(string(issuer)) + " must match " + which + ", so whether Entra accepts or evaluates this expression is not documented",
			Source:    expressionSource,
		})
		missing = true
	}
	if !missing {
		return term
	}
	return eval.Term{"sub": eval.Unknown("required claim missing")}
}

// unbalanced is the widening for an expression with an odd number of
// single quotes. Where a comparand ends is then undecidable, and which text
// a piece holds would depend on which clause the stray quote sits in, so
// the expression is judged as a whole by a count no reordering changes.
func (r *reading) unbalanced() eval.Term {
	r.doubt(trust.Anomaly{
		Kind:      trust.Unmodelled,
		Claim:     "sub",
		Construct: "unbalanced quote",
		Message:   "the expression holds an odd number of single quotes, so where its claim names and comparands begin and end cannot be read; Microsoft's grammar encloses each in single quotes, so nothing the expression says about the token is modelled",
		Source:    expressionSource,
	})
	return eval.Term{"sub": eval.Unknown("unparseable expression")}
}

// tooManyClauses is the widening for an expression past clauseCap: nothing
// of it is read, and the count is the fact, which no reordering changes.
func (r *reading) tooManyClauses(n int) eval.Term {
	r.doubt(trust.Anomaly{
		Kind:      trust.Unmodelled,
		Claim:     "sub",
		Construct: "clause count",
		Message:   "the expression has " + strconv.Itoa(n) + " clauses; Microsoft documents at most four claims for any issuer, and this parser reads at most " + strconv.Itoa(clauseCap) + " clauses, so nothing the expression says about the token is modelled",
		Source:    expressionSource,
	})
	return eval.Term{"sub": eval.Unknown("too many clauses")}
}

// unparseable is the whole-expression widening: every piece outside the
// grammar is named, not only the first, so that the facts do not depend on
// the order the clauses were written in; sub carries the Unknown; and no
// clause survives, because the operator that was not understood may have
// governed every one of them.
func (r *reading) unparseable(expression string, broken []string) eval.Term {
	if strings.TrimSpace(expression) == "" {
		r.doubt(trust.Anomaly{
			Kind:      trust.Unmodelled,
			Claim:     "sub",
			Construct: "empty expression",
			Message:   "claimsMatchingExpression.value is empty; Microsoft documents no empty expression, so nothing the expression says about the token is modelled",
			Source:    expressionSource,
		})
		return eval.Term{"sub": eval.Unknown("unparseable expression")}
	}
	for _, text := range broken {
		if text == "" {
			r.doubt(trust.Anomaly{
				Kind:      trust.Unmodelled,
				Claim:     "sub",
				Construct: "empty clause",
				Message:   "the expression has an empty clause: \"and\" is written with nothing on one side of it; Microsoft's grammar joins clauses of the form claims['<name>'] eq '<value>' or claims['<name>'] matches '<value>' with \"and\", so nothing the expression says about the token is modelled",
				Source:    expressionSource,
			})
			continue
		}
		r.doubt(trust.Anomaly{
			Kind:      trust.Unmodelled,
			Claim:     "sub",
			Construct: "unparseable clause",
			Message:   quote(text) + " is not of the form claims['<name>'] eq '<value>' or claims['<name>'] matches '<value>'; Microsoft documents no other form, so nothing the expression says about the token is modelled",
			Source:    expressionSource,
		})
	}
	return eval.Term{"sub": eval.Unknown("unparseable expression")}
}

// credentialClaims are the two claims every credential constrains whatever
// its issuer: the subject an expression must match and the audience the
// document sets. A name that differs from one of them only in case folds to
// it even under an issuer whose claims Microsoft does not list, so that the
// doubt lands on the claim a reader asks about rather than on a spelling no
// token carries.
var credentialClaims = []trust.ClaimKey{"aud", "sub"}

// claimKey is the key a clause constrains. A name that matches a documented
// claim only in ASCII case is read as that claim: if Entra folds case the
// reading is exact, and if it does not the clause names a claim no token
// carries and Entra admits nothing, so the folded reading is never narrower
// than Entra. The doubt is recorded either way, because which of the two it
// is cannot be known from the document. The fold is ASCII alone: a name
// from another script that Unicode folding would equate with a documented
// one, a long s for an s, is a claim no token carries, not a hand's slip.
func (r *reading) claimKey(name string, lang language) trust.ClaimKey {
	key := trust.ClaimKey(name)
	if _, listed := lang.operators[key]; listed || slices.Contains(credentialClaims, key) {
		return key
	}
	for _, documented := range slices.Concat(slices.Sorted(maps.Keys(lang.operators)), credentialClaims) {
		if equalFoldASCII(string(documented), name) {
			r.doubt(trust.Anomaly{
				Kind:      ClaimFolded,
				Claim:     documented,
				Construct: claimLookup(name),
				Message:   claimLookup(name) + " is read as " + claimLookup(string(documented)) + "; Microsoft does not say whether claim names are case-sensitive",
				Source:    expressionSource,
			})
			return documented
		}
	}
	return key
}

// equalFoldASCII reports whether two names differ at most in the case of
// ASCII letters. Every other byte must match exactly.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// constraint is the set one clause admits for its claim. The checks run
// from the fact that decides the most to the one that decides the least: an
// issuer Microsoft does not document leaves nothing to say about the clause;
// a comparand the language does not define cannot be compared under any
// operator; a claim or operator outside the issuer's list has no documented
// behaviour; and only then is the clause an exact value or a pattern. The
// construct each fact names is the thing outside the language, the issuer,
// the claim lookup or the operator word, so that a reporter can count the
// credentials that share it; the clause itself is quoted in the sentence.
func (r *reading) constraint(c clause, key trust.ClaimKey, lang language, documented bool, issuer trust.IssuerRef) eval.StringSet {
	widen := func(reason, construct, message string) eval.StringSet {
		r.doubt(trust.Anomaly{Kind: trust.Unmodelled, Claim: key, Construct: construct, Message: message, Source: expressionSource})
		return eval.Unknown(reason)
	}
	operators, listed := lang.operators[key]
	switch {
	case !documented && issuer == "":
		return widen("undocumented issuer", quote(string(issuer)), "Microsoft documents claim expressions for GitHub, GitLab and Terraform Cloud issuers; whether Entra evaluates "+quote(c.text)+" without an issuer is not documented")
	case !documented:
		return widen("undocumented issuer", quote(string(issuer)), "Microsoft documents claim expressions for GitHub, GitLab and Terraform Cloud issuers; whether Entra evaluates "+quote(c.text)+" for issuer "+quote(string(issuer))+" is not documented")
	case strings.Contains(c.comparand, "''"):
		return widen("escaped quote", "escaped quote", "the comparand of "+quote(c.text)+" holds a doubled single quote; Microsoft says single quotes are escape characters and does not say what a doubled quote means")
	case c.comparand == "":
		return widen("empty comparand", "empty comparand", quote(c.text)+" compares against the empty string; Microsoft does not say whether Entra accepts an empty comparand")
	case !listed:
		return widen("undocumented claim", claimLookup(string(key)), "Microsoft does not list "+claimLookup(string(key))+" for issuer "+quote(string(issuer))+", so whether Entra evaluates "+quote(c.text)+" is not documented")
	case !slices.Contains(operators, c.operator):
		return widen("undocumented operator", truncated(c.operator), "Microsoft lists "+quoteEach(operators)+" for "+claimLookup(string(key))+" under issuer "+quote(string(issuer))+", not "+quote(c.operator)+", so whether Entra evaluates "+quote(c.text)+" is not documented")
	case c.operator == "eq":
		return eval.Exact(c.comparand)
	}
	set := eval.Glob(c.comparand)
	if set.IsTop() {
		r.note(trust.Anomaly{
			Kind:      UndocumentedAcceptance,
			Claim:     key,
			Construct: truncated(c.comparand),
			Message:   quote(c.text) + " matches every value; Microsoft does not say whether Entra accepts a pattern that constrains nothing",
			Source:    expressionSource,
		})
	}
	return set
}

// quoteEach renders a list of operators for a sentence: "eq" and "matches".
func quoteEach(words []string) string {
	quoted := make([]string, len(words))
	for i, w := range words {
		quoted[i] = quote(w)
	}
	if len(quoted) == 1 {
		return quoted[0]
	}
	return strings.Join(quoted[:len(quoted)-1], ", ") + " and " + quoted[len(quoted)-1]
}
