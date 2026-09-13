package join

import (
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// A witness is an identity both grants of a pair admit: a token, aud set
// aside, that satisfies one term of the overlap. It is built from the
// overlap's own constraints, then confirmed against both grants with
// Admits, so the sentence never names an identity the lattice would not
// accept. Where the walk below finds nothing, or gives up, the pair is not
// dropped: only IsEmpty may drop a pair, and the Link says that no example
// could be built.
//
// The walk decides glob-and-glob exactly when it runs to the end, which
// the lattice cannot yet; its negative answer is deliberately not used as
// a decision, because it does not always run to the end, and because a
// second decision procedure needs its own laws and belongs in eval beside
// the automata unit. This file moves there when that unit lands.

type token = map[trust.ClaimKey]string

// shape is what the join can read of one claim's constraint. eval keeps
// its node types unexported and its rendering canonical, and finding IDs
// are already content-addressed on that rendering, so the join reads the
// rendering back and keeps only what a witness and a sentence need.
type shape struct {
	kind    shapeKind
	text    string  // the value of an exactValue, the pattern of a globPattern
	members []shape // the patterns of an allOf, the alternatives of an anyOf
}

type shapeKind int

const (
	exactValue  shapeKind = iota // one value, every character literal
	globPattern                  // a StringLike pattern
	allOf                        // the strings matching every pattern
	anyOf                        // the strings matching any member
)

// constraint is one claim of a Term as the join reads it: either the shape
// of its constraint, or the fact that it admits everything as far as the
// lattice could evaluate, which is the one case a Term keeps without a
// shape.
type constraint struct {
	claim trust.ClaimKey
	top   bool
	shape shape
}

// constraintsOf reads a Term in claim order, so that everything built from
// it, witness and sentence alike, is a function of the Term alone.
func constraintsOf(term eval.Term) []constraint {
	out := make([]constraint, 0, len(term))
	for _, k := range slices.Sorted(maps.Keys(term)) {
		if term[k].IsTop() {
			out = append(out, constraint{claim: k, top: true})
			continue
		}
		out = append(out, constraint{claim: k, shape: readShape(term[k].String())})
	}
	return out
}

// witnessOf is the first identity, in canonical term order, that the
// overlap's own constraints yield and that both sides admit. A claim the
// overlap leaves unconstrained is witnessed by leaving it out: an absent
// claim satisfies only a constraint that admits everything.
//
// Both sides are asked, not the overlap alone and not one side: the
// overlap is the lattice's Meet, which today never admits more than both
// operands, but a witness is a promise printed to a customer, and the
// promise is kept by asking the grants themselves rather than by trusting
// that every future widening in eval stays on the safe side.
func witnessOf(overlap, sideA, sideB eval.AdmittedSet) token {
	for _, term := range overlap.Terms() {
		if tok, ok := termWitness(constraintsOf(term)); ok && sideA.Admits(tok) && sideB.Admits(tok) {
			return tok
		}
	}
	return nil
}

func termWitness(constraints []constraint) (token, bool) {
	tok := token{}
	for _, c := range constraints {
		if c.top {
			continue
		}
		v, ok := c.shape.witness()
		if !ok {
			return nil, false
		}
		tok[c.claim] = v
	}
	return tok, true
}

// witness is a string the shape contains: a value is its own, a pattern's
// is its shortest instance, an intersection's is the shortest string every
// pattern matches, and a union's is the first of its members' in canonical
// order.
func (s shape) witness() (string, bool) {
	switch s.kind {
	case exactValue:
		return s.text, true
	case globPattern:
		return sharedInstance([]string{s.text})
	case allOf:
		return sharedInstance(s.patterns())
	}
	for _, m := range s.members {
		if w, ok := m.witness(); ok {
			return w, true
		}
	}
	return "", false
}

func (s shape) patterns() []string {
	out := make([]string, len(s.members))
	for i, m := range s.members {
		out[i] = m.text
	}
	return out
}

// sharedInstance is the shortest string every pattern matches, when one
// exists and the walk finds it within walkBound states. It walks the
// product of the patterns: a state is one position in each pattern; a star
// may be skipped, or absorb a rune without moving; consuming a rune
// advances every pattern at once, and the rune is the one a literal fixes,
// on which every literal must agree, or "x" when only stars and "?" are
// waiting. Level by level, each level closed under star skips before any
// rune is consumed, so the first accepting state is reached by the fewest
// runes, and among those by the plainest path: stars deleted rather than
// filled.
func sharedInstance(patterns []string) (string, bool) { return shortestShared(patterns, walkBound) }

// walkBound caps the states one walk visits. Patterns of the form *a*b*c*
// make the shortest common instance the shortest common supersequence
// problem, NP-hard in the number of patterns, so no bound covers every
// input and the walk gives up past this one; a pair is then a Link with no
// example, never a missing Link, since the walk's negative answer is never
// a decision. Measured on the shapes the tests hold: a branch pin against
// a repository pin visits 66 states, the four patterns of the
// three-patterns case 485, the eight of golden case 11 need 126,481 and
// are past the cap, and the cap stops the six-pattern supersequence shape
// of TestSharedInstanceGivesUpPastTheBound in about fifty milliseconds
// instead of never.
const walkBound = 1 << 16

// shortestShared is sharedInstance under an explicit bound.
func shortestShared(patterns []string, bound int) (string, bool) {
	w := walk{units: make([][]rune, len(patterns)), seen: map[string]bool{}, bound: bound}
	for i, p := range patterns {
		w.units[i] = []rune(p)
	}
	frontier := w.skipStars([]step{{at: make([]int, len(patterns))}})
	for len(frontier) > 0 {
		for _, s := range frontier {
			if w.accepting(s.at) {
				return string(s.text), true
			}
		}
		if w.exhausted() {
			return "", false
		}
		var next []step
		for _, s := range frontier {
			if r, at, ok := w.consume(s.at); ok {
				next = append(next, step{at, append(slices.Clone(s.text), r)})
			}
		}
		frontier = w.skipStars(next)
	}
	return "", false
}

// walk is one search over the product of the patterns: the patterns as
// runes, the states already reached, and the most it may reach.
type walk struct {
	units [][]rune
	seen  map[string]bool
	bound int
}

// step is one state of the walk and the runes that reached it.
type step struct {
	at   []int
	text []rune
}

func (w *walk) exhausted() bool { return len(w.seen) >= w.bound }

// skipStars closes a level under star skips: every state reachable from the
// given ones without consuming a rune, in a fixed order, dropping any
// state an earlier level already reached, since re-reaching it with more
// runes can find nothing shorter. Past the bound it adds nothing, and the
// level it returns is partial; the caller checks it for an accepting
// state, which is still a real one, then stops.
func (w *walk) skipStars(states []step) []step {
	var out []step
	var visit func(s step)
	visit = func(s step) {
		k := stateKey(s.at)
		if w.exhausted() || w.seen[k] {
			return
		}
		w.seen[k] = true
		out = append(out, s)
		for i, u := range w.units {
			if s.at[i] < len(u) && u[s.at[i]] == '*' {
				next := slices.Clone(s.at)
				next[i]++
				visit(step{next, s.text})
			}
		}
	}
	for _, s := range states {
		visit(s)
	}
	return out
}

func (w *walk) accepting(at []int) bool {
	for i, u := range w.units {
		if at[i] != len(u) {
			return false
		}
	}
	return true
}

// consume advances every pattern over one rune, when one rune satisfies
// them all.
func (w *walk) consume(at []int) (rune, []int, bool) {
	r, fixed := 'x', false
	next := slices.Clone(at)
	for i, u := range w.units {
		if at[i] == len(u) {
			return 0, nil, false
		}
		switch c := u[at[i]]; c {
		case '*':
		case '?':
			next[i]++
		default:
			if fixed && c != r {
				return 0, nil, false
			}
			r, fixed = c, true
			next[i]++
		}
	}
	return r, next, true
}

func stateKey(at []int) string {
	parts := make([]string, len(at))
	for i, p := range at {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}

// readShape reads the rendering eval produced for a constraint that is not
// top. Anything else is a rendering this package was never taught, and the
// only safe answer is to stop: guessing at it could put a wrong witness
// into an Established sentence.
func readShape(text string) shape {
	s, rest, ok := parseShape(text)
	if !ok || rest != "" {
		panic("join: cannot read the constraint rendering " + strconv.Quote(text))
	}
	return s
}

// parseShape reads one shape from the front of text and returns what
// follows it. The grammar is eval's String: a quoted value, "like:" and a
// quoted pattern, or a parenthesised list of members joined by " | " or
// " & ".
func parseShape(text string) (shape, string, bool) {
	switch {
	case strings.HasPrefix(text, "like:"):
		pattern, rest, ok := quoted(text[len("like:"):])
		return shape{kind: globPattern, text: pattern}, rest, ok
	case strings.HasPrefix(text, `"`):
		value, rest, ok := quoted(text)
		return shape{kind: exactValue, text: value}, rest, ok
	case strings.HasPrefix(text, "("):
		return parseMembers(text[1:])
	}
	return shape{}, "", false
}

// parseMembers reads two or more members under one separator, then the
// closing parenthesis. An intersection holds patterns only, which is how
// eval builds it and what the walk relies on.
func parseMembers(text string) (shape, string, bool) {
	first, rest, ok := parseShape(text)
	if !ok {
		return shape{}, "", false
	}
	kind, sep := anyOf, " | "
	if strings.HasPrefix(rest, " & ") {
		kind, sep = allOf, " & "
	}
	members := []shape{first}
	for strings.HasPrefix(rest, sep) {
		var m shape
		if m, rest, ok = parseShape(rest[len(sep):]); !ok {
			return shape{}, "", false
		}
		members = append(members, m)
	}
	if len(members) < 2 || !strings.HasPrefix(rest, ")") {
		return shape{}, "", false
	}
	if kind == allOf && slices.ContainsFunc(members, func(m shape) bool { return m.kind != globPattern }) {
		return shape{}, "", false
	}
	return shape{kind: kind, members: members}, rest[1:], true
}

// quoted reads one Go-quoted string, the form eval writes with
// strconv.QuoteToASCII, and returns the text after it.
func quoted(text string) (string, string, bool) {
	q, err := strconv.QuotedPrefix(text)
	if err != nil {
		return "", "", false
	}
	v, err := strconv.Unquote(q)
	return v, text[len(q):], err == nil
}
