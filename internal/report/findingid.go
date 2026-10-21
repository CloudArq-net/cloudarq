package report

import (
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"slices"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// A finding's stable id and its pairing key.
//
// The id is the SHA-256, in lowercase hex, of the JSON array
//
//	["cloudarq.finding/1", rule, role, issuer, condition]
//
// where rule is the finding's rule id; role is the role's ARN as the
// bundle lists it, path and partition included; issuer is the grant's
// issuer as the answer writes it, a provider's normalised URL, a SAML
// provider's ARN, or aws:sts for an AWS principal, whose account is a
// claim of its term and so is part of the condition; and condition is an
// array of strings: the finding's condition, conditionOf's, and after it
// the conditions its statement writes that its term does not read,
// unreadOf's, as the finding writes both. The pairing key is the SHA-256, in
// lowercase hex, of the same array without the condition:
//
//	["cloudarq.finding/1", rule, role, issuer]
//
// The array is written as JSON with no whitespace, and each string as
// encoding/json writes one: a quotation mark and a backslash escaped with
// a backslash; a control character as \b, \f, \n, \r or \t where it is
// one of those and as \u00 and two lowercase hex digits otherwise; "<",
// ">", "&", U+2028 and U+2029 as \u and four lowercase hex digits; and any
// other character as its UTF-8 bytes. The engine reads no document that
// is not UTF-8, so no two strings are written alike. This form is fixed
// for "cloudarq.finding/1": a reader may recompute either key from the
// recipe, and a key made any other way would be another name at the head
// of the array, never another form under this one.
//
// What a key is kept across, and what moves it, follows from the array.
// Nothing the parser drops before it makes a term is in it: whitespace,
// the order of the statements, their Sids. Nothing two writings read alike
// is either, since the term is the engine's reading and the conditions it
// does not read are written in one form: the case of a condition key, a
// value alone or in a list of one, the order of a list's values and their
// repeats, an account bare or as its root ARN. One way in written in two
// statements is two populations with one id. Anything else moves the id:
// a value or an operator that changes the reading, a condition the engine
// does not read added, removed or given other values, another rule, and
// the role renamed or moved, which moves the pairing key too. A term reads
// the same through releases of the engine that read it alike; one that
// reads what an earlier release left Unknown gives the finding a new id
// and keeps its pairing key, which tells a reader the reading changed.

// findingVersion heads the array a finding's keys are the hash of.
const findingVersion = "cloudarq.finding/1"

// keysOf is the id and the pairing key of the finding of rule that a way
// in through issuer, whose condition is condition, gives the role whose
// ARN is role.
func keysOf(rule, role string, issuer trust.IssuerRef, condition []string) (id, pairing string) {
	e := &encoder{}
	e.b = append(e.b, '[')
	for i, s := range [...]string{findingVersion, rule, role, string(issuer)} {
		e.comma(i)
		e.quote(s)
	}
	head := len(e.b)
	e.b = append(e.b, ',', '[')
	for i, c := range condition {
		e.comma(i)
		e.quote(c)
	}
	e.b = append(e.b, ']', ']')
	idSum := sha256.Sum256(e.b)
	pairingSum := sha256.Sum256(append(e.b[:head:head], ']'))
	return hex.EncodeToString(idSum[:]), hex.EncodeToString(pairingSum[:])
}

// conditionOf is a way in's condition: each claim its term holds, in the
// claims' byte order, written claim=rendering, the constraint rendered as
// the answer's admits renders it, in which an Unknown is "?" and, in
// parentheses and each quoted, the parser's names for what it could not
// read, as an operator, a key, a policy variable or a principal as written,
// never the sentence saying why, which is the caveat's. A term that holds
// no claim is an empty condition, never a missing one.
func conditionOf(term eval.Term) []string {
	out := make([]string, 0, len(term))
	for _, claim := range slices.Sorted(maps.Keys(term)) {
		out = append(out, string(claim)+"="+term[claim].String())
	}
	return out
}

// unreadOf is the conditions a statement writes that a grant of it does
// not read, as aws.Document.Unread names them, each written "operator key
// values": the operator and the key lower-cased in ASCII, as the parser
// files a key, and values the JSON array of the values, in byte order,
// each once. They are in byte order too, each once, since the order of a
// statement's conditions, and a condition written twice, mean nothing.
func unreadOf(unread []aws.Condition) []string {
	written := make([]string, 0, len(unread))
	for _, c := range unread {
		e := &encoder{}
		e.b = append(e.b, '[')
		for i, v := range slices.Compact(slices.Sorted(slices.Values(c.Values))) {
			e.comma(i)
			e.quote(v)
		}
		e.b = append(e.b, ']')
		written = append(written, fold(c.Operator)+" "+fold(c.Key)+" "+string(e.b))
	}
	slices.Sort(written)
	return slices.Compact(written)
}

// isSumHex reports whether s is a key as keysOf writes one: a SHA-256 in
// lowercase hex.
func isSumHex(s string) bool {
	if len(s) != hex.EncodedLen(sha256.Size) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !('0' <= s[i] && s[i] <= '9' || 'a' <= s[i] && s[i] <= 'f') {
			return false
		}
	}
	return true
}

// identify writes the id and the pairing key of each finding of an answer
// to the role whose ARN is role, from the condition and the unread
// conditions the finding writes, which the policy as read gave it. A
// finding whose unread conditions are not known, because the engine could
// not tell which of its statement's principals its grant was read from, is
// left without keys rather than given another's.
func (a *Answer) identify(role string) {
	for i := range a.Grants {
		g := &a.Grants[i]
		for j := range g.Populations {
			f := g.Populations[j].Finding
			if f == nil || f.Condition == nil || f.Unread == nil {
				continue
			}
			f.ID, f.PairingKey = keysOf(f.Rule, role, trust.IssuerRef(g.Issuer), slices.Concat(f.Condition, f.Unread))
		}
	}
}
