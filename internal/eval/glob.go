package eval

import (
	"strconv"
	"strings"
)

// glob is a StringSet described by an AWS StringLike pattern.
//
// The matcher is written by hand rather than compiled to a regexp so that
// "everything except * and ? is a literal" holds by construction instead of by
// correctly escaping every regex metacharacter. The class of bug where a "."
// or "+" in a pattern silently widens the set cannot exist here, because no
// character is ever interpreted.
type glob struct {
	pattern string
	// segments is the pattern split on "*". Within a segment every rune is a
	// literal except '?', which stands for exactly one rune. A segment is a
	// fixed-width predicate, which is what makes the search below correct.
	segments [][]rune
}

// Glob builds the set of strings matching pattern under AWS StringLike rules:
// "*" is zero or more of any character, including "/" and ":"; "?" is exactly
// one; everything else is a literal; the match is anchored and case-sensitive.
//
// A pattern with no metacharacters is a singleton and is normalised to Exact.
// A pattern made only of stars admits everything and is normalised to Any, so
// that IsTop can answer truthfully instead of conservatively.
func Glob(pattern string) StringSet {
	if !strings.ContainsAny(pattern, "*?") {
		return exact{pattern}
	}
	if strings.Trim(pattern, "*") == "" {
		return full{}
	}
	parts := strings.Split(pattern, "*")
	segments := make([][]rune, len(parts))
	for i, p := range parts {
		segments[i] = []rune(p)
	}
	return glob{pattern: pattern, segments: segments}
}

func (g glob) Contains(v string) bool { return matchSegments(g.segments, []rune(v)) }

// IsEmpty is false: every pattern has a witness, obtained by deleting each "*"
// and replacing each "?" with any character.
func (g glob) IsEmpty() bool { return false }

// IsTop is false: a pattern that survives Glob's normalisation contains a
// literal or a "?", and therefore rejects the empty string.
func (g glob) IsTop() bool { return false }

func (g glob) Meet(o StringSet) StringSet { return meet(g, o) }
func (g glob) Join(o StringSet) StringSet { return join(g, o) }
func (g glob) String() string             { return "like:" + strconv.Quote(g.pattern) }

// matchSegments reports whether v matches the segments, which are the pieces
// of a pattern between its stars.
//
// The first segment is pinned to the start and the last to the end; that is
// what anchoring means. Each middle segment is then placed at the leftmost
// position after the previous one. Leftmost is always safe: any later
// placement leaves a shorter remainder for the segments that follow, so if a
// match exists at all the greedy placement finds it.
func matchSegments(segments [][]rune, v []rune) bool {
	first, last := segments[0], segments[len(segments)-1]
	if len(segments) == 1 {
		return len(v) == len(first) && matchAt(first, v, 0)
	}
	if !matchAt(first, v, 0) {
		return false
	}
	i := len(first)
	end := len(v) - len(last)
	if end < i || !matchAt(last, v, end) {
		return false
	}
	for _, seg := range segments[1 : len(segments)-1] {
		j := i
		for ; j+len(seg) <= end && !matchAt(seg, v, j); j++ {
		}
		if j+len(seg) > end {
			return false
		}
		i = j + len(seg)
	}
	return true
}

// matchAt reports whether seg matches v starting at rune offset i.
func matchAt(seg, v []rune, i int) bool {
	if i+len(seg) > len(v) {
		return false
	}
	for k, r := range seg {
		if r != '?' && r != v[i+k] {
			return false
		}
	}
	return true
}
