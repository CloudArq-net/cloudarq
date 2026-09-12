package eval

import "strconv"

// StringSet is a set of possible values for a single claim.
//
// Implementations are immutable. Every operation returns a new value.
type StringSet interface {
	// Contains reports whether v is a member. Exact for every implementation.
	Contains(v string) bool

	// Meet is intersection: the values admitted by BOTH sets.
	Meet(StringSet) StringSet

	// Join is union: the values admitted by EITHER set.
	Join(StringSet) StringSet

	// IsEmpty reports whether the set is PROVABLY empty.
	// It returns false whenever emptiness cannot be decided. Never the reverse.
	IsEmpty() bool

	// IsTop reports whether the set provably admits every string.
	IsTop() bool

	// String renders the set for humans and for golden files. Stable across runs.
	String() string
}

// Exact is the singleton {v}. The value is literal: "*" and "?" in v are
// ordinary characters, which is what an Exact claim value means in a policy.
func Exact(v string) StringSet { return exact{v} }

// Any is the set of every string.
func Any() StringSet { return full{} }

// None is the set with no members.
func None() StringSet { return empty{} }

// exact is the singleton set.
type exact struct{ v string }

func (e exact) Contains(v string) bool { return v == e.v }
func (e exact) IsEmpty() bool          { return false }
func (e exact) IsTop() bool            { return false }

func (e exact) Meet(o StringSet) StringSet { panic("not implemented") }
func (e exact) Join(o StringSet) StringSet { panic("not implemented") }

// full is the set of every string.
type full struct{}

func (full) Contains(string) bool { return true }
func (full) IsEmpty() bool        { return false }
func (full) IsTop() bool          { return true }

func (full) Meet(o StringSet) StringSet { panic("not implemented") }
func (full) Join(o StringSet) StringSet { panic("not implemented") }

// empty is the set with no members.
type empty struct{}

func (empty) Contains(string) bool { return false }
func (empty) IsEmpty() bool        { return true }
func (empty) IsTop() bool          { return false }

func (empty) Meet(o StringSet) StringSet { panic("not implemented") }
func (empty) Join(o StringSet) StringSet { panic("not implemented") }

// Rendering.
//
// Values and patterns are quoted so that String is injective: an Exact whose
// value happens to start with "like:" must not render the same as a Glob, and
// a value containing " | " must not be mistaken for two members of a union.
// Finding IDs are content-addressed on this text, so two different sets with
// the same rendering would collide.

func (e exact) String() string { return strconv.Quote(e.v) }
func (g glob) String() string  { return "like:" + strconv.Quote(g.pattern) }
func (full) String() string    { return "*" }
func (empty) String() string   { return "∅" }
