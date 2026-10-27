package report

import (
	"slices"
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/ring"
	"github.com/CloudArq-net/cloudarq/internal/vendors"
)

// Listed is the vendor that publishes an AWS account as its own, and what
// it uses the account for on each page it does so, from the list
// internal/vendors holds. It names an owner and places nothing: an account
// a vendor publishes is an outsider until the reader declares it, and one
// declared is theirs and still carries the vendor.
type Listed struct {
	Vendor string      `json:"vendor"`
	Uses   []ListedUse `json:"uses"`
}

// ListedUse is one page that publishes the account: what the vendor uses
// it for, the page, and the date the page was read.
type ListedUse struct {
	Use     string `json:"use"`
	Source  string `json:"source"`
	Checked string `json:"checked"`
}

// listed is the vendor that publishes owner o as its own, for an AWS
// account the grant's principal names by an ARN of its partition and that
// account; nil for any other owner. A principal written as the account id
// alone writes no partition, and the same id in another partition is
// another account, so the list names no account but one an ARN places.
func (p placed) listed(o ring.Owner) *Listed {
	if o.Namespace != ring.NamespaceAWS || o.Scope != ring.ScopeAccount || o.Kind != ring.KindID {
		return nil
	}
	partition, ok := arnPartition(p.principal, o.Value)
	if !ok {
		return nil
	}
	a, ok := vendors.Lookup(partition, o.Value)
	if !ok {
		return nil
	}
	l := &Listed{Vendor: a.Vendor, Uses: make([]ListedUse, len(a.Sources))}
	for i, s := range a.Sources {
		l.Uses[i] = ListedUse{Use: s.Use, Source: s.URL, Checked: s.Checked}
	}
	return l
}

// arnPartition is the partition an ARN is in, arn:partition:service:
// region:account:resource, when the account it names is account.
func arnPartition(arn, account string) (string, bool) {
	f := strings.SplitN(arn, ":", 6)
	if len(f) != 6 || f[0] != "arn" || f[4] != account {
		return "", false
	}
	return f[1], true
}

// principalOf is the principal a grant was read from, as the leaves its
// statement writes it at hold it, or "" where it writes none. Every leaf
// holds the same text, and a kept answer keeps the leaves, so an answer
// placed again without its policy reads the same principal.
func principalOf(leaves []Leaf) string {
	if len(leaves) == 0 {
		return ""
	}
	return leaves[0].Text
}

// keptPrincipal is the principal a kept grant was read from, as its ways
// keep it.
func keptPrincipal(populations []Population) string {
	for _, p := range populations {
		if p.Way != nil && len(p.Way.Principal) > 0 {
			return principalOf(p.Way.Principal)
		}
	}
	return ""
}

// sameListed reports whether two owners name the same vendor for the same
// uses on the same pages, or neither names one.
func sameListed(a, b *Listed) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Vendor == b.Vendor && slices.Equal(a.Uses, b.Uses)
}

// listedWords is what a sentence says of an owner a vendor publishes, right
// after naming it: ", which Datadog publishes as its own". It names the
// vendor alone, once however many pages publish the account: what each
// page says the account is used for is a label written for a list, which
// --explain and the JSON give as written. It is empty for an owner no
// vendor publishes, so a sentence that names none reads as it did before
// the list.
func listedWords(o named) string {
	if o.listed == nil {
		return ""
	}
	return ", which " + o.listed.Vendor + " publishes as its own"
}

// listedAside is listedWords closed by a comma, for a sentence that goes
// on past the owner.
func listedAside(o named) string {
	if w := listedWords(o); w != "" {
		return w + ","
	}
	return ""
}

// listedFirst is two owners named one by one, the one a vendor publishes
// first when no vendor publishes the other, so that the vendor named right
// after it is said of it alone: named after the second, the vendor would
// follow both, and the account no vendor publishes would read as the
// vendor's. Other owners are kept in their order.
func listedFirst(owners []named) []named {
	if len(owners) == 2 && owners[0].listed == nil && owners[1].listed != nil {
		return []named{owners[1], owners[0]}
	}
	return owners
}

// namedAside is listedAside of owners named one by one, as ownersSpan
// names one alone and counts more.
func namedAside(owners []named) string {
	if len(owners) == 1 {
		return listedAside(owners[0])
	}
	return ""
}

// listedLines are what --explain says of a population's owners that a
// vendor publishes: one line for each page, its fields the account, the
// vendor, what the page says the account is used for, the page and the
// date it was read, each as the list writes it.
func listedLines(owners []Owner) []string {
	var lines []string
	for _, o := range owners {
		if o.Listed == nil {
			continue
		}
		for _, u := range o.Listed.Uses {
			lines = append(lines, "         listed "+withoutControls(o.Label)+" · "+withoutControls(o.Listed.Vendor)+" · "+withoutControls(u.Use)+" · "+withoutControls(u.Source)+" · checked "+withoutControls(u.Checked))
		}
	}
	return lines
}
