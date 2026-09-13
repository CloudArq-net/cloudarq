// Package join computes what no single system's API returns: facts that
// are true of a pair of independently controlled systems. Everything
// before it can, in principle, be built by whoever holds one cloud; a Link
// cannot, because it needs evidence from both sides, and the constructor
// refuses to build one without it.
//
// The first join, J6, is the cross-cloud counterparty fan-out: one
// counterparty, from one issuer, admitted by more than one target. It is a
// grouping over trust.Grants that already exist, so it needs no collector,
// and it is the concrete answer to "why not the cloud's own analyser":
// AWS's tool does not consider the state of any external account, and
// cannot see an Azure application at all. "The same counterparty" is set
// overlap between admitted identities, never string equality: repo:acme/*
// on one side and repo:acme/infra:* on the other fan out, and the lattice's
// Meet says so where a comparison of subjects could not.
//
// Three rules keep the package from under-reporting. A pair whose overlap
// cannot be proved empty always yields a Link, Indeterminate when nothing
// more can be said, because an undecided overlap reported as absence is
// the failure this package exists to prevent; the search for an example
// identity is bounded, and giving it up is not a decision either. A Link
// is Established only when an identity both sides admit was built and
// confirmed, both sides name their issuer, both admitted sets are exact,
// both effects read Allow, every evidence record on both sides names its
// call and its status and is conclusive, and no statement on either
// target that denies, or whose effect could not be read and so may deny,
// can touch the overlap or was read too doubtfully to say; the reason
// otherwise says which of those failed. And whatever the parser or the
// collector could not read is a doubt, never a gap: a grant whose effect
// could not be read pairs and casts doubt rather than vanishing, a grant
// whose issuer is not named pairs with every issuer's grants, and a
// record that names no call or no status is named as such in the sentence
// rather than used to refuse the pair.
//
// A target is a TargetRef, compared as a struct; two targets are two
// systems as far as this package can tell, since a Grant carries no cloud
// and no account by design. A pair of roles in one account is therefore a
// pair, proved by whatever the collector read for each, once when it read
// one response for both; folding same-account pairs is the reporter's.
// Links are pairwise: a counterparty trusted by n targets yields n(n-1)/2
// of them, and the reporter folds those into one cluster and one sentence.
// Every Link carries a sentence printable to a customer verbatim, in the
// product's vocabulary: what is admitted, by whom, with an example when
// one adds anything, and never more of a long list than a sentence holds.
//
// The package is pure. It imports nothing that does IO, reads the clock
// or draws randomness, reads no files, and knows no cloud: which provider
// a target belongs to is the parser's knowledge, and the fixtures'.
package join
