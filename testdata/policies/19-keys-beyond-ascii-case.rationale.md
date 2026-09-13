# 19 — a key with a letter outside ASCII case is read under a folding nobody documents

Hand-written fixture, 2026-09-13. The keys spell `ſ`, LATIN SMALL
LETTER LONG S, and `K`, KELVIN SIGN, as JSON escapes so that the
difference from `s` and `K` is visible in the file; the parser sees the
decoded letter either way.

## Document

`DenyWithALongSInTheProvider` is a Deny for the GitHub provider on
`token.actions.githubuſercontent.com:sub`, the provider identifier
spelled with a long s. `LongSInTheClaim` pins `aud` and
`token.actions.githubusercontent.com:ſub`, the claim spelled with
one. `TwoSpellingsThatMayBeOneKey` pins `aud`, then
`token.actions.githubuſercontent.com:sub` to the main branch and
`token.actions.githubusercontent.com:sub` to the dev branch.
`AsciiKeyOnAProviderSpelledBeyondASCII` trusts the provider
`oidc.eks.us-west-2.amazonaws.com/id/K1`, whose path holds the Kelvin
sign, and pins `oidc.eks.us-west-2.amazonaws.com/id/K1:sub`, spelled with
an ASCII K.

## Expected

- `DenyWithALongSInTheProvider`: a Deny that denies nothing, inexact, with
  an `unmodelled-construct` anomaly naming the key whose sentence is
  `the condition key "token.actions.githubuſercontent.com:sub" holds a letter outside ASCII with case variants of its own; AWS documents no folding for it, so which key it names is not known and the claim is not constrained`,
  and the Deny-not-applied anomaly.
- `LongSInTheClaim`:
  `{aud="sts.amazonaws.com", ſub=?("folding of token.actions.githubusercontent.com:ſub")}`,
  inexact, with the same shape of anomaly on the claim `ſub`; a token with
  `aud` alone is admitted.
- `TwoSpellingsThatMayBeOneKey`:
  `{aud="sts.amazonaws.com", sub=?("possible duplicate key token.actions.githubuſercontent.com:sub"), token.actions.githubuſercontent.com:sub=?("folding of token.actions.githubuſercontent.com:sub", "possible duplicate key token.actions.githubuſercontent.com:sub")}`,
  inexact, with the folding anomaly on the long-s key and a
  `duplicate-key` anomaly on `sub` whose sentence is
  `the keys "token.actions.githubuſercontent.com:sub" and "token.actions.githubusercontent.com:sub" under StringEquals are one key if AWS folds letters outside ASCII, which no page documents; a JSON decoder would then keep one and the deployed policy may carry either, so the claim is not constrained`.
  The reason names the first spelling in the block. Both branches are
  admitted.
- `AsciiKeyOnAProviderSpelledBeyondASCII`: issuer
  `https://oidc.eks.us-west-2.amazonaws.com/id/K1`, everything,
  inexact, with a caveat on the claim
  `oidc.eks.us-west-2.amazonaws.com/id/k1:sub` and an `unmodelled-construct`
  anomaly naming the key whose sentence is
  `the condition key "oidc.eks.us-west-2.amazonaws.com/id/K1:sub" is a claim of the Federated principal "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/K1" if AWS folds letters outside ASCII, which no page documents, so which key it names is not known and the claim is not constrained`.
  A token with `sub` `system:serviceaccount:ns:sa` is admitted.

A sentence quotes the customer's text with every letter outside ASCII as
its escape, so that a lookalike letter cannot pass for the one it
resembles; a rendered claim key is bare, so the long s appears as itself
there.

## Why

The Condition page: "Context key names are not case-sensitive. For
example, including the aws:SourceIP context key is equivalent to testing
for AWS:SourceIp." Every example is an ASCII letter, and no page read says
what IAM does with a letter outside ASCII that has case variants of its
own. Unicode simple case folding, which Go's `strings.EqualFold` and
`unicode.SimpleFold` implement from CaseFolding.txt, equates U+017F with
`s` and U+212A KELVIN SIGN with `k`; a Unicode lower-casing does not fold
U+017F at all. Whether IAM applies either, or neither, is not stated.

A parser has to choose a folding, and every choice is wrong on one of two
documents. Folding the long s reads the first statement's key as the
provider's `sub` and applies the Deny to the main branch; if IAM does not
fold, that key names no context key, the condition never matches and the
Deny denies nothing, so the parser reported a role as narrower than it is.
Not folding reads the second statement's key as a claim no token carries
and admits nobody; if IAM folds, AWS admits the main branch. An earlier
draft used three foldings at once, ASCII for the claim part, simple case
folding for the provider identifier and Unicode lower-casing for the
duplicate test, and the third statement met its two constraints in a
provably empty set, reported exact, because the duplicate test did not see
what the identifier comparison saw.

So the folding this parser applies to a key is the one AWS documents by
example, ASCII case, and a key holding any letter outside ASCII with case
variants is Unknown, declared, whoever it would belong to: sound under
either reading, because Unknown admits everything an Allow could and makes
a Deny inapplicable. Two spellings in one block that are one key under
simple case folding but not under ASCII folding may be a duplicate, in
which case a decoder keeps either copy; every constraint in such a group
is Unknown, the ASCII spelling included, and the sentence says why. A
letter with no case at all, a CJK ideograph say, raises no such question
and is kept as written.

"Case variants of its own" means any case mapping the Unicode tables
give the letter, not simple folding alone. U+0130 LATIN CAPITAL LETTER I
WITH DOT ABOVE lower-cases to `i` and U+0131 LATIN SMALL LETTER DOTLESS I
upper-cases to `I`, the Turkic casing of the ASCII letter, yet neither is
in a simple-folding orbit, because CaseFolding.txt gives U+0130 only a
full mapping and marks the Turkic pair `T`; a case-insensitive comparison
built on upper- and lower-casing, as Java's `equalsIgnoreCase` is, equates
both with `i`. A draft that asked simple folding alone read
`token.actions.gıthubusercontent.com:sub` as another provider's key,
exact, and admitted nobody. An exhaustive scan of the Unicode tables in Go
1.27.1 found those two letters to be the only ones a case mapping moves
that simple folding does not, and no letter that another letter maps onto
without mapping out itself, so asking the four mappings of the letter
itself is complete.

The same question arises when the letter sits in the provider identifier
rather than the key, which is the fourth statement: under a Unicode
folding the ASCII key names the provider's own `sub`, under ASCII folding
it names another provider's key. The key is compared with the identifier
under simple case folding as well as ASCII folding, and a key that the
wider folding would make the provider's own is Unknown with the sentence
above, exactly as a key holding such a letter is. A key another provider
owns under every folding, `gitlab.com:sub` say, stays that provider's
whatever the identifier holds.

When a block holds a certain duplicate, two spellings that are one key
under ASCII folding, beside a spelling that is the same key only under the
wider folding, the sentence states the certain fact first and the
conditional one after it, each with the spellings it is about:
`the key "token.actions.githubusercontent.com:sub" appears more than once under StringEquals; "token.actions.githubusercontent.com:sub" and "token.actions.githubuſercontent.com:sub" are one key if AWS folds letters outside ASCII, which no page documents; a JSON decoder keeps one and the deployed policy may carry either, so the claim is not constrained`.
A draft described that group as only a possible duplicate, which was false
for two of the three keys it named.

## Sources

- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html (fetched 2026-09-13)
- https://www.unicode.org/Public/UCD/latest/ucd/CaseFolding.txt, entries 017F, 0130, 0131 and 212A
- Go `unicode.SimpleFold`, `unicode.ToUpper`, `unicode.ToLower`, `strings.EqualFold`, `strings.ToLower`, checked on Go 1.27.1: SimpleFold(U+017F) = 'S', EqualFold("ſ", "s") = true, ToLower("ſ") = "ſ", SimpleFold(U+0130) = U+0130, ToLower(U+0130) = 'i', SimpleFold(U+0131) = U+0131, ToUpper(U+0131) = 'I'
- specs/B2-aws-trust-policy-parser.md §3, §4
