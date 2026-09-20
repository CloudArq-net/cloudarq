package report

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/eval"
)

// Constraint is one claim's constraint in a form the page can render and a
// witness can be built from. eval keeps its node types unexported, and its
// canonical rendering is the one stable description of a StringSet it
// offers, the one finding IDs are addressed on, so the constraint is read
// back from that rendering; a rendering this reader was never taught is an
// error, not a guess.
type Constraint struct {
	// Kind is exact, like, union, intersection, unknown or any.
	Kind string `json:"kind"`
	// Value is the value of an exact or the pattern of a like.
	Value string `json:"value,omitempty"`
	// Reason is why an unknown was not evaluated, as the engine recorded it.
	Reason string `json:"reason,omitempty"`
	// Members are the alternatives of a union or the patterns of an
	// intersection, in canonical order.
	Members []Constraint `json:"members,omitempty"`
}

const (
	kindExact        = "exact"
	kindLike         = "like"
	kindUnion        = "union"
	kindIntersection = "intersection"
	kindUnknown      = "unknown"
	kindAny          = "any"
)

// constraintOf reads the constraint a term holds on one claim.
func constraintOf(s eval.StringSet) (Constraint, error) {
	if eval.IsUnknown(s) {
		return Constraint{Kind: kindUnknown, Reason: eval.Reason(s)}, nil
	}
	if s.IsTop() {
		return Constraint{Kind: kindAny}, nil
	}
	text := s.String()
	c, rest, err := parseConstraint(text)
	if err == nil && rest != "" {
		err = fmt.Errorf("trailing %q", rest)
	}
	if err != nil {
		return Constraint{}, fmt.Errorf("read the constraint %s: %w", text, err)
	}
	return c, nil
}

// parseConstraint reads one constraint from the front of eval's rendering
// and returns what follows it: a quoted value, "like:" and a quoted
// pattern, or a parenthesised list joined by " | " or " & ".
func parseConstraint(text string) (Constraint, string, error) {
	switch {
	case strings.HasPrefix(text, "like:"):
		pattern, rest, err := unquote(text[len("like:"):])
		return Constraint{Kind: kindLike, Value: pattern}, rest, err
	case strings.HasPrefix(text, `"`):
		value, rest, err := unquote(text)
		return Constraint{Kind: kindExact, Value: value}, rest, err
	case strings.HasPrefix(text, "("):
		return parseMembers(text[1:])
	}
	return Constraint{}, "", fmt.Errorf("no constraint at %q", text)
}

func parseMembers(text string) (Constraint, string, error) {
	first, rest, err := parseConstraint(text)
	if err != nil {
		return Constraint{}, "", err
	}
	kind, sep := kindUnion, " | "
	if strings.HasPrefix(rest, " & ") {
		kind, sep = kindIntersection, " & "
	}
	members := []Constraint{first}
	for strings.HasPrefix(rest, sep) {
		var m Constraint
		if m, rest, err = parseConstraint(rest[len(sep):]); err != nil {
			return Constraint{}, "", err
		}
		members = append(members, m)
	}
	if len(members) < 2 || !strings.HasPrefix(rest, ")") {
		return Constraint{}, "", fmt.Errorf("unclosed list at %q", rest)
	}
	// eval intersects patterns only; anything else in one is not its rendering
	if kind == kindIntersection && slices.ContainsFunc(members, func(m Constraint) bool { return m.Kind != kindLike }) {
		return Constraint{}, "", fmt.Errorf("an intersection of something other than patterns at %q", text)
	}
	return Constraint{Kind: kind, Members: members}, rest[1:], nil
}

// unquote reads one Go-quoted string, the form eval writes.
func unquote(text string) (string, string, error) {
	q, err := strconv.QuotedPrefix(text)
	if err != nil {
		return "", "", fmt.Errorf("no quoted string at %q", text)
	}
	v, err := strconv.Unquote(q)
	return v, text[len(q):], err
}

// witness is the simplest value the constraint admits: an exact is its own
// value, a pattern has every star removed and every ? replaced by x, a
// union takes the first alternative that has one. An intersection has none
// until eval decides pattern overlap; the join package walks it privately,
// and a second walk here would be a second decision procedure. Any and
// unknown have none either, because a witness leaves such claims out.
func (c Constraint) witness() (string, bool) {
	switch c.Kind {
	case kindExact:
		return c.Value, true
	case kindLike:
		return strings.Map(func(r rune) rune {
			switch r {
			case '*':
				return -1
			case '?':
				return 'x'
			}
			return r
		}, c.Value), true
	case kindUnion:
		for _, m := range c.Members {
			if w, ok := m.witness(); ok {
				return w, true
			}
		}
	}
	return "", false
}
