// Package gcp reads Google Cloud workload identity pool providers, the
// documents by which a pool trusts tokens from an outside issuer, into
// provider-neutral trust.Grants, and binds them to the IAM policy members
// that let the pool's identities reach a service account or a resource,
// whether the policy comes alone or inside the results of a Cloud Asset
// policy search.
//
// It exists because a provider admits identities into a pool by an
// attribute condition written in CEL, and the checks that read such a
// condition today match it against shapes they expect: a condition they
// do not recognise is skipped, which reports the provider as narrower than
// it is, and a principalSet binding on attribute.NAME is read as a
// constraint on a claim named NAME, which is wrong whenever the attribute
// mapping is not the identity, Google's own default mapping for AWS
// providers included. This parser parses the whole CEL syntax, evaluates
// the subset a condition can express over token claims, ==, in over a
// list of string literals, startsWith, endsWith, contains, &&, || and !
// over one comparison, and makes everything else Unknown on the claim it
// constrains, or on the whole grant when the claim cannot be named, with
// a caveat and an anomaly that says what was met. A modelled form written
// where an operand belongs, a comparison compared with true, say, is
// outside the subset by its position, and the anomaly names the operand
// as written rather than calling == or startsWith unmodelled. A reference
// to google.subject or attribute.NAME is attributed to a token claim only
// when the mapping maps it by a bare assertion.CLAIM; any other mapping
// expression leaves the clause, and the binding, unattributable, and the
// grant is read as the whole pool with the reason stated. google.groups,
// which Google describes as a set of groups, is Unknown on the claim it
// maps to under every form, since the lattice holds one value per claim.
// A reserved word after a dot names a field, as cel-go and cel-cpp read
// it. An Unknown never narrows: it is the top of the lattice under both
// Meet and Join, so a clause that could not be read can only widen what
// is reported.
//
// What Google's reference pages do not settle, and which way each reading
// errs. A token missing a claim the condition compares: CEL makes the
// comparison an error, and an expression that must "output a boolean
// representing whether to allow the federation" cannot allow on an error,
// so such a token is read as rejected; if Google allowed on an error the
// sets here would be narrower, and that is the one assumption stated here
// that errs in the unsafe direction. A raw string literal is read as the
// characters between its quotes, backslashes included, because the
// language definition says a literal preceded by r or R "does not
// interpret escape sequences"; the assumption is that Google's CEL keeps
// to the definition here, and if it interpreted escapes in a raw literal
// the value read would be a different string, a set neither wider nor
// narrower than Google's, on a literal no page read shows. A
// triple-quoted literal holding an unescaped carriage return is read as
// both implementations read it, as a line feed, but the language
// definition says only that such a literal may hold newlines, so the claim
// it constrains is Unknown rather than an Exact on either reading. The
// condition's length is counted in characters, as Google's sentence
// counts it. JSON member names are read under either of the two spellings
// proto3's JSON mapping accepts, and the mapping does not say whether a
// parser folds case; a member that matches a documented name only in case
// is not read, and neither is the documented member beside it, and what
// the member bears on is Unknown with the doubt stated, as for a member
// written twice: under a reader that folded case, the audience list, the
// condition or a custom mapping in place of Google's AWS default would
// apply, and neither that reading nor the one that ignores the member
// contains the other. An issuerUri that is not an https URL is read as
// the issuer it names once normalised, with the fact recorded: "Must be
// an HTTPS endpoint" is Google's sentence, and whether the API refuses
// another scheme is not stated. The document names one host and no
// reading of it admits a token from another, so the reading is not
// narrower than Google; it is the narrower of the two readings in the
// join, where a blank issuer pairs a grant with every counterparty, and it
// is chosen because that pairing would report a doubt about the scheme as
// the absence of an issuer. Under an AWS provider the account is spelt as
// the AWS parser's claim, so that a join pairs the two documents on the
// account exactly, and the ARN keeps Google's own name, arn: Google's
// assertion.arn holds the STS form of an assumed role and the AWS parser's
// aws:principalarn the IAM form a trust policy writes, so an Exact on one
// never equals an Exact on the other, and a shared name would pair nothing
// while claiming to; the rewrite from one form to the other is the join's
// to learn.
//
// A binding is read as the widest thing it may be wherever the pages do
// not settle what it is, so that a binding that may exist never reads as
// absent. Whether Google decodes percent escapes in a principal identifier
// is not documented, so an escape is never decoded and never compared as
// written either: in the fixed text of a principal, the host and the
// segments projects, locations and workloadIdentityPools, it leaves
// whether the member is a pool principal at all undecided, and the member
// is read as the principal it resembles; in the pool it leaves whether the
// member names this provider's pool undecided, and the member is read as
// binding it; in the selector's kind it leaves the form undecided, and the
// member is read as the whole pool; in a value it leaves the claim
// Unknown. Fixed text spelt in another ASCII case is read the same way,
// as the principal it resembles with the doubt stated: RFC 3986 makes a
// scheme case-insensitive, and whether IAM's reader folds case anywhere
// is not stated. The scheme alone is never matched by escape, since RFC
// 3986 gives a scheme no percent-encoding; text holding "%" before "://"
// is no scheme, and a member under a scheme that is neither principal nor
// principalSet in any case is one of the other kinds of principal Google
// documents, not a binding on a pool. A pool named by project ID on one
// side and by number on the other cannot be placed from the two documents
// alone and is read as the same pool, with the doubt stated; a member
// whose pool differs in a value segment under every reading names another
// pool and is no binding on the provider. A member that names the pool
// but selects from it by a form Google documents for no workload identity
// pool, or for the GKE pool alone, a subject under principalSet://, a star
// under principal://, namespace/NAMESPACE, an empty or absent selector,
// is read as the whole pool: whether IAM accepts it and what it would
// select are not stated, and the union of every reading is at most the
// pool. Google says google.subject cannot exceed 127 bytes; a longer value
// that a binding selects, or the condition writes, for the claim the
// subject maps to is one no credential maps to, and it is kept as written
// with the set declared an upper bound rather than proven empty, since
// the limit is documentation rather than a refusal this parser observed,
// which errs wide. A disabled or soft-deleted provider keeps the set its
// condition admits, declared an upper bound: existing tokens still grant
// access, one update re-enables it, and a reversible flag is not a proof
// of emptiness. The default audience is derived only from a name of the
// shape the API returns, with the project by number; any other name
// leaves aud Unknown rather than an Exact on a string Google may not use.
// An IAM condition on a binding is not evaluated and the binding is read
// as unconditional, with the doubt stated; the role is not modelled, and
// the bound grant is on whatever target the caller names. A policy inside
// a search result holds only the bindings that matched the query, which is
// Google's statement, and a page of results that carries a nextPageToken
// is refused, so that a later page never reads as absent; a page of
// providers that carries one is refused by ParseProviders for the same
// reason, and ParsePage hands the token back for the collector to follow,
// because a binding on the whole pool depends on every provider in it.
//
// An anomaly's Source is the member it is about, spelt as Google
// documents it and dotted from the provider: name, state, disabled,
// provider_config for the union as a whole, oidc.issuerUri,
// oidc.allowedAudiences, aws.accountId, attributeMapping.<key>,
// attributeCondition for every fact about the condition, saml or x509;
// a miscased member is named as written. A fact about a binding points
// into the policy: bindings[i].members[j] or bindings[i].condition, under
// policy. when the policy came inside a search result and under
// results[k].policy. when that result came in a page.
//
// The package is pure: no IO, no clock, no randomness, enforced by
// test/arch. It is total over arbitrary bytes and bounded in time: the
// lists a document can inflate, audiences and the values under in, are
// read up to a cap past which the claim is Unknown with the count stated,
// never truncated; a condition past Google's own length is not read; and
// the term cap of the lattice widens a disjunctive normal form that grows
// past it to everything, with the lattice's own caveat.
package gcp
