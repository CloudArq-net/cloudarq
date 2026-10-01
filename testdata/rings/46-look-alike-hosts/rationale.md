# 46 — provider hosts spelled with letters that case folding may turn into ASCII ones

A trap at the seam for a grant placed nearer than its population. `KelvinSignForK` names
`toKen.actions.githubusercontent.com`, with U+212A KELVIN SIGN where GitHub's host has a `k`;
`DottedCapitalIForI` names `oİdc.eks.us-east-1.amazonaws.com`, with U+0130 LATIN CAPITAL LETTER I
WITH DOT ABOVE where an EKS cluster's host has an `i`. Each letter is written as its JSON escape,
the only form in which a policy carries it: AWS refuses a policy document that holds a character
above U+00FF as itself. The owners declared are GitHub's `acme` and the real EKS cluster.

**Expected.**
- `KelvinSignForK` → **anyone**, unknown: the parser names no issuer for the principal.
- `DottedCapitalIForI` → **anyone**, unknown: the same.

Declaring `acme` and the real cluster moves neither.

**Why.** Case folding takes each of these letters to an ASCII one, so a host read through a
folding becomes GitHub's host or the cluster's. The provider in IAM is whatever URL was
registered, and AWS says that URL should be the `iss` its tokens carry: a token from GitHub or from
the cluster does not carry this one. Nothing read for this case says whether IAM reads a
provider's host through a case folding, so the engine reads neither spelling as the other, and
names no issuer. Read as GitHub's issuer, the first statement would have been a named outsider,
pinned to `acme`; read as the cluster's, the second would have moved into the user's own ring
on the declaration of the real cluster, for an issuer whoever registered the look-alike host runs.
Every census host is ASCII, and the registry turns away any issuer that is not.

> "212A; C; 006B; # KELVIN SIGN" — https://www.unicode.org/Public/17.0.0/ucd/CaseFolding.txt (U+212A folds to U+006B `k`) · read 2026-09-26
> "0130; T; 0069; # LATIN CAPITAL LETTER I WITH DOT ABOVE" — https://www.unicode.org/Public/17.0.0/ucd/CaseFolding.txt (under the Turkic mapping, U+0130 folds to U+0069 `i`) · read 2026-09-26
> "The URL must begin with https:// and should correspond to the iss claim in the provider's OpenID Connect ID tokens." — https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateOpenIDConnectProvider.html · read 2026-09-23
> "Policy documents can contain only the following Unicode characters: horizontal tab (U+0009), linefeed (U+000A), carriage return (U+000D), and characters in the range U+0020 to U+00FF." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html · read 2026-09-26
