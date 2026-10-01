package eval

import "unicode/utf8"

// Shape is a StringSet read as the node it is: which kind of set, the value
// or pattern that defines it, and the members of a union or an
// intersection. Contains answers which values a set admits; a layer that
// must reason about how a constraint is written reads it here instead. The
// rings are that layer: whether a pattern pins an owner depends on how far
// its literal prefix runs, and whether a union pins one depends on every
// member. The join and the report each read the rendering back into such a
// structure; a third reader would be a third copy of its grammar, so the
// package that builds the nodes reports them.
//
// A Shape is plain data, built afresh on every read: changing one changes
// nothing in the set, which stays immutable.
type Shape struct {
	Kind ShapeKind
	// Text is the value of an exact set, every character literal, or the
	// pattern of a glob, as Exact and Glob were given them. It is empty for
	// every other kind.
	Text string
	// Members are the alternatives of a union, each an exact value, a glob
	// or an intersection, or the patterns of an intersection, each a glob:
	// two or more, in the order String renders them. Every other kind has
	// none.
	Members []Shape
}

// ShapeKind is which node a StringSet is. The zero value is ShapeUnknown,
// the kind that claims nothing about which values a set holds and no
// certainty about it either, so a Shape that was never read can neither be
// taken for a constraint to narrow on nor be reported as exact.
type ShapeKind int

const (
	// ShapeUnknown is every string, because a constraint existed and could
	// not be evaluated. Reason on the set says why.
	ShapeUnknown ShapeKind = iota
	// ShapeAny is every string.
	ShapeAny
	// ShapeNone is no string, proven.
	ShapeNone
	// ShapeExact is the one string Text.
	ShapeExact
	// ShapeGlob is every string the StringLike pattern Text matches.
	ShapeGlob
	// ShapeUnion is every string at least one member admits.
	ShapeUnion
	// ShapeIntersection is every string all its patterns match. Whether two
	// patterns share a string is undecided in this package, so a Shape of
	// this kind may admit nothing; it never says so.
	ShapeIntersection
)

// ShapeOf reads the node s is. A StringSet this package did not build is
// read as ShapeUnknown, as is the Unknown it builds: neither exposes a
// structure the view could vouch for, and Unknown is the kind that claims
// nothing a caller could narrow on.
func ShapeOf(s StringSet) Shape {
	switch n := s.(type) {
	case exact:
		return Shape{Kind: ShapeExact, Text: n.v}
	case glob:
		return Shape{Kind: ShapeGlob, Text: n.pattern}
	case full:
		return Shape{Kind: ShapeAny}
	case empty:
		return Shape{Kind: ShapeNone}
	case union:
		return Shape{Kind: ShapeUnion, Members: shapesOf(n.members)}
	case inter:
		return Shape{Kind: ShapeIntersection, Members: shapesOf(n.members)}
	}
	return Shape{Kind: ShapeUnknown}
}

func shapesOf[S StringSet](members []S) []Shape {
	out := make([]Shape, len(members))
	for i, m := range members {
		out[i] = ShapeOf(m)
	}
	return out
}

// LiteralPrefix is what every string a StringLike pattern matches begins
// with, as far as the pattern's text vouches for it: the run before its
// first character that is not a literal. "*" and "?" end the run, a "?"
// because it stands for any one character. So does U+FFFD, whether written
// or produced by a byte that is not UTF-8: the matcher reads both as
// U+FFFD, which a value's own invalid bytes also become, so neither stands
// for itself.
//
// A caller asking whether a pattern confines a value to one owner asks it
// of this prefix and never of the pattern: the owner in "repo:acm?/*" is not
// "acm?", and the one in "repo:*@123456/*" is not 123456.
//
// It reads a pattern. An exact value's "*" and "?" are literal characters,
// so its prefix is the value itself, which a caller has already.
func LiteralPrefix(pattern string) string {
	for i, r := range pattern {
		if r == '*' || r == '?' || r == utf8.RuneError {
			return pattern[:i]
		}
	}
	return pattern
}
