# 06 — the issuer is trusted, nothing else is pinned

**Expected:** `Everything`. AWS and GCP only; Azure is inexpressible.

**Why.** The AWS statement pins only `aud`. The harness adds each provider's own
audience to the reference set (`Case.Audiences`), so beyond `aud` the identity set is
unconstrained: any repository on GitHub whose
workflow requests the right audience can assume the role. This is the finding the product
exists to print, and it must render as `Everything`, not as an error and not as an empty
set. GCP without an `attributeCondition` admits every subject the same way. Azure is
declared inexpressible with the reason in `internal/trust/conformance.go`: a federated
identity credential must pin the subject, and a flexible one must match `sub` together
with an immutable claim, so "every subject from this issuer" cannot be written.

**Witnesses.** `main`, the look-alike organisation, and the empty token: `Everything`
admits a token with no claims at all.

**Counters.** None; nothing is rejected.
