// Package ring places every grant of a trust policy at a distance from the
// user: anyone at all, anyone on the issuing platform, a named outsider,
// the user's own pipelines, or the user's own people. Two
// populations a trust policy does not reveal sit beside the rings rather
// than among them: the sign-ins of a SAML provider, which its metadata
// decides, and the callers of a cloud service, which no trust policy
// carries.
//
// A grant's place is the nearest ring guaranteed to hold every identity able
// to present a credential the grant admits. The rings are distance levels,
// not nested sets: yours is nearer than outsider, not inside it. Each
// alternative of a grant's admitted set is placed on its own and the grant
// takes the outermost, because over-approximation is the one direction this
// engine may err in: a grant placed nearer than its population is the
// worst answer it can print.
//
// What decides a place is data, never code. Which claims name a tenant, the
// forms a subject takes, the characters an owner's name may hold, whether an
// issuer mints tokens to people with no account: the census supplies these
// as Facts, the AWS parser answers for the pseudo-issuers it names and for
// the principals it could not model, and the user supplies the owners
// it declares as its own. A fact nobody verified reads the cautious way,
// and nothing here reads a sentence another package wrote.
//
// The package does no IO, which test/arch checks, and reads no clock: a
// placement must be the same bytes on every run, which the determinism
// tests check.
package ring
