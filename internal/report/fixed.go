package report

import (
	"errors"
	"fmt"
	"slices"
)

// The whole fixed policy, made where the policy is. An answer carries a
// proven fix's edit and the digest of the policy it leaves, never that
// policy's text, which is the reader's own; the caller that holds the
// bundle asks for it here, for one role and one principal, and gets it only
// where the role's answer, with the owners declared, proves the edit.

// AppendFixed appends to dst the trust policy of the bundle's role whose
// ARN is arn with the principal written at [start, end) of it removed, or,
// where that would leave it no statement, the policy that lets no one in
// which replaces it, as the role's answer with the owners declared, one a
// line, proves that edit,
// and returns the extended buffer: {"v":1,"policy":…,"sha256":…}, the
// policy as text and its digest, which is the digest the fix names. Where
// the bundle or the role is not one the engine reads, no grant is read from
// a principal written at those offsets, or the answer proves no edit that
// removes it, it renders {"v":1,"error":…} with why, and no policy.
func AppendFixed(dst, bundle, owners []byte, arn string, start, end int) []byte {
	e := &encoder{b: dst}
	saved := e.begin()
	e.num("v", Version)
	if policy, err := fixedPolicy(bundle, owners, arn, start, end); err != nil {
		e.str("error", err.Error())
	} else {
		e.str("policy", string(policy))
		e.str("sha256", digest(policy))
	}
	e.end(saved)
	return e.b
}

// fixedPolicy is the role's trust policy with the principal at [start, end)
// removed, or the policy that replaces it where removing the principal
// would leave it no statement, made again by the edit the role's proven fix
// names, and checked against the digest the fix carries.
func fixedPolicy(bundle, owners []byte, arn string, start, end int) ([]byte, error) {
	b, err := ReadBundle(bundle)
	if err != nil {
		return nil, err
	}
	at := slices.IndexFunc(b.Roles, func(r BundleRole) bool { return r.Arn == arn })
	if at < 0 {
		return nil, fmt.Errorf("no role of this bundle has the ARN %+q", arn)
	}
	document := b.Roles[at].Document
	answer, p := answerPlaced(document, owners, b.recognised())
	if answer.Error != "" {
		return nil, errors.New(answer.Error)
	}
	var fixes []*Fix
	read := -1
	for i, w := range p.read.written {
		if w.Start != start || w.End != end || w.End == 0 {
			continue
		}
		if read < 0 {
			read = i
		}
		for _, pop := range answer.Grants[i].Populations {
			fixes = append(fixes, pop.Way.Fix)
		}
	}
	fix := chosenFix(fixes)
	switch {
	case read < 0:
		return nil, fmt.Errorf("no grant of the role is read from a principal written at bytes %d-%d of its trust policy, so nothing is removed", start, end)
	case fix != nil && fix.Status == fixUnproven:
		return nil, errors.New(fix.Sentence)
	case fix == nil || fix.Status != fixProven:
		return nil, fmt.Errorf("the engine proves no edit that removes the principal written at bytes %d-%d of the role's trust policy", start, end)
	}
	edited, _, err := p.read.edit(read)
	if err != nil || digest(edited) != fix.Edit.SHA256 {
		return nil, fmt.Errorf("the policy made again does not have the digest the fix names, so it is not given")
	}
	return edited, nil
}

// chosenFix is, of the fixes of the populations read from one principal,
// the one fixedPolicy answers by: a proven one, which is the one asked for,
// and failing that the first unproven one, which says why no edit is
// proven, and failing that the first in words. nil entries are populations
// with no fix.
func chosenFix(fixes []*Fix) *Fix {
	for _, status := range []string{fixProven, fixUnproven, fixWords} {
		if at := slices.IndexFunc(fixes, func(f *Fix) bool { return f != nil && f.Status == status }); at >= 0 {
			return fixes[at]
		}
	}
	return nil
}
