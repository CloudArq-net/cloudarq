# 04 — the immutable subject format

**Expected:** `{sub = "repo:acme@123456/infra@456789:ref:refs/heads/main"}` on every provider.

**Why.** GitHub's newer subject format carries the owner id and the repository id inside
`sub` itself, so a plain exact match on `sub` is already immune to renames and namespace
reuse. Every provider can pin an exact string, so all three documents admit the same set
and the harness judges them `Equal`. The point of the case is that the parsers keep `@`
and the digits verbatim: any normalisation of the subject would break the pin.

**Witnesses.** The immutable spelling itself.

**Counters.** The name-based spelling of the same branch (a different string); the
immutable spelling of the `dev` branch; the empty token.
