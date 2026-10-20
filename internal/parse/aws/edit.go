package aws

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
)

// Removed is what RemovePrincipal takes out of a policy to remove one
// principal: the least that takes the principal out and leaves every other
// byte as it was.
type Removed int

const (
	// RemovedPrincipal is the principal alone, out of a list of its kind
	// that names others.
	RemovedPrincipal Removed = iota + 1
	// RemovedKind is the member of Principal the principal is the only
	// value of, as "AWS": "111122223333", beside other members.
	RemovedKind
	// RemovedStatement is the statement, whose Principal names nothing but
	// the principal.
	RemovedStatement
)

// RemovePrincipal is raw with one principal removed: the one whose string
// literal is written at [start, end), as Written reads it. It removes the
// least that takes that principal out: the principal from a list of its
// kind that names others, with the comma beside it; the member of Principal
// the principal is the only value of, beside other members; or, when the
// Principal member it sits in names nothing else, the statement, out of the
// Statement member that holds it. Every other byte stays as written. What
// removing it does to who the policy lets in is not decided here: whoever
// asks reads the result again.
//
// It refuses, and returns no bytes, unless the bytes at [start, end) are
// exactly one principal string under a Principal member of a statement, and
// that statement writes its Effect once, as "Allow", and writes no
// NotPrincipal. Removing a principal from a Deny, or from beside a
// NotPrincipal, which names who is excluded rather than who is admitted,
// can let more in. Offsets that land anywhere else are refused, never moved
// to the nearest principal: a guessed edit is an edit to something the
// caller did not name.
func RemovePrincipal(raw []byte, start, end int) ([]byte, Removed, error) {
	root, err := parseTree(raw)
	if err != nil {
		return nil, 0, fmt.Errorf("the policy is not read: %w", err)
	}
	if root.kind != kindObject {
		return nil, 0, errors.New("the policy is not an object")
	}
	for i, m := range root.members {
		if m.name != "Statement" {
			continue
		}
		if m.value.kind == kindObject {
			if r, found := locate(m.value, start, end); found {
				return r.remove(raw, root, i)
			}
			continue
		}
		if m.value.kind != kindArray {
			continue
		}
		for j, s := range m.value.items {
			if s.kind != kindObject {
				continue
			}
			if r, found := locate(s, start, end); found {
				return r.remove(raw, m.value, j)
			}
		}
	}
	return nil, 0, fmt.Errorf("the bytes at %d-%d are not one principal written under a statement's Principal", start, end)
}

// located is where a principal string sits in a statement: the statement,
// the Principal value that holds it, the member of that value it is under
// and, for a principal in a list, its index in the list; principal is nil
// for a Principal that is the string itself.
type located struct {
	statement, principal *value
	member               int // the index of the member of principal the string is under
	item                 int // the string's index in that member's list, -1 when it is the member's value
}

// locate finds the principal string written at [start, end) under a
// Principal member of s.
func locate(s *value, start, end int) (located, bool) {
	at := func(v *value) bool { return v.kind == kindString && v.start == start && v.end == end }
	for _, m := range s.members {
		if m.name != "Principal" {
			continue
		}
		if at(m.value) {
			return located{statement: s}, true
		}
		if m.value.kind != kindObject {
			continue
		}
		for k, pm := range m.value.members {
			if at(pm.value) {
				return located{statement: s, principal: m.value, member: k, item: -1}, true
			}
			if pm.value.kind != kindArray {
				continue
			}
			for i, item := range pm.value.items {
				if at(item) {
					return located{statement: s, principal: m.value, member: k, item: i}, true
				}
			}
		}
	}
	return located{}, false
}

// remove cuts the principal out of raw, once the statement it sits in is
// one a principal may be removed from. holder is the value that holds the
// statement, the root object or the Statement member's list, and at is the
// statement's index in it.
func (l located) remove(raw []byte, holder *value, at int) ([]byte, Removed, error) {
	effects, allow, notPrincipal := 0, false, false
	for _, m := range l.statement.members {
		switch m.name {
		case "Effect":
			effects++
			allow = m.value.kind == kindString && m.value.text == "Allow"
		case "NotPrincipal":
			notPrincipal = true
		}
	}
	switch {
	case effects != 1 || !allow:
		return nil, 0, errors.New(`the statement does not write its Effect once, as "Allow", and a principal is removed only from an Allow statement, since removing one from a Deny lets more in`)
	case notPrincipal:
		return nil, 0, errors.New("the statement writes NotPrincipal, which names who is excluded rather than who is admitted, and removing a principal beside it may let more in")
	}
	if l.principal == nil {
		return cutElement(raw, holder, at), RemovedStatement, nil
	}
	list := l.principal.members[l.member].value
	switch {
	case l.item >= 0 && len(list.items) > 1:
		return cutElement(raw, list, l.item), RemovedPrincipal, nil
	case len(l.principal.members) > 1:
		return cutElement(raw, l.principal, l.member), RemovedKind, nil
	}
	return cutElement(raw, holder, at), RemovedStatement, nil
}

// cutElement is raw without element i of c, an object's member or a list's
// item, and the separator beside it: up to where the next element starts,
// or, for the last of several, from where the one before it ends. An only
// element goes with everything between c's delimiters, leaving {} or [].
// A member starts at its name.
func cutElement(raw []byte, c *value, i int) []byte {
	starts, ends := c.elements()
	from, to := starts[i], ends[i]
	switch {
	case len(starts) == 1:
		from, to = c.start+1, c.end-1
	case i < len(starts)-1:
		to = starts[i+1]
	default:
		from = ends[i-1]
	}
	return slices.Concat(raw[:from], raw[to:])
}

// LetNoOneIn is the trust policy that lets no one in, written to replace
// raw where removing a principal would leave raw with no statement, a
// policy IAM refuses: "MalformedPolicyDocument: Could not parse the policy:
// Statement is empty!". Its one statement denies sts:AssumeRole, the action
// an AWS principal assumes a role through (assumeActions), to every AWS
// principal, which IAM accepts as a trust policy. It is not the Deny that
// keeps everyone out: with no Allow statement the policy lets no one in
// through any action, and the Deny is there because a trust policy needs a
// statement. The Version raw writes comes first, its value as written;
// raw's other members do not. A policy that writes no Version gets none.
// A Version IAM refuses is refused here, since the result would keep it
// and IAM would refuse that too: written more than once ("Duplicate JSON
// key: Version."), not a string ("The text does not match the expected
// JSON data type String."), or a string that is neither language version
// ("The version 2013-10-17 is not valid. Use one of the following
// versions: 2008-10-17, 2012-10-17."), in IAM Access Analyzer's words for
// an AWS::IAM::AssumeRolePolicyDocument. What the result admits is not
// decided here: whoever asks reads it again.
// versionKept ends the refusal of a Version IAM refuses: why it refuses
// the replacement too.
const versionKept = ", which IAM refuses, and the policy that would replace it keeps the Version as written"

func LetNoOneIn(raw []byte) ([]byte, error) {
	root, err := parseTree(raw)
	if err != nil {
		return nil, fmt.Errorf("the policy is not read: %w", err)
	}
	if root.kind != kindObject {
		return nil, errors.New("the policy is not an object")
	}
	var version *value
	for _, m := range root.members {
		if m.name != "Version" {
			continue
		}
		if version != nil {
			return nil, errors.New("the policy writes Version more than once" + versionKept)
		}
		version = m.value
	}
	out := []byte("{\n")
	if version != nil {
		switch {
		case version.kind != kindString:
			return nil, errors.New("Version is " + describe(version) + ", not a string" + versionKept)
		case version.text != "2012-10-17" && version.text != "2008-10-17":
			return nil, errors.New("Version " + strconv.QuoteToASCII(version.text) + ` is neither "2012-10-17" nor "2008-10-17"` + versionKept)
		}
		out = append(append(append(out, `  "Version": `...), version.bytes()...), ",\n"...)
	}
	return append(out, `  "Statement": [
    {
      "Sid": "DenyEveryone",
      "Effect": "Deny",
      "Principal": {"AWS": "*"},
      "Action": "sts:AssumeRole"
    }
  ]
}`...), nil
}

// elements are where each element of an object or a list starts and ends.
func (v *value) elements() (starts, ends []int) {
	for _, m := range v.members {
		starts, ends = append(starts, m.start), append(ends, m.value.end)
	}
	for _, item := range v.items {
		starts, ends = append(starts, item.start), append(ends, item.end)
	}
	return starts, ends
}
