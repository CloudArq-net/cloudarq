# Architecture

## The kernel

A trust condition compiles to a set expression over claim-space.

```go
type StringSet interface {   // Exact | Glob | Any | None | Unknown
    Contains(string) bool
    Meet(StringSet) StringSet   // AND -- conditions within a statement
    Join(StringSet) StringSet   // OR  -- across statements, and across condition values
}

type AdmittedSet struct {
    Terms []map[ClaimKey]StringSet   // disjunction of conjunctions
}
```

Five operations fall out of one structure: satisfiability, tautology detection, set difference,
containment, and a **witness** — a concrete token the deployed condition accepts. The witness is
the thing a stranger cannot dismiss. Not a severity label; a JWT payload.

### Unknown is the top element

`Unknown` is **absorbing under `Join`** and the **identity under `Meet`**.

`Unknown | X = Unknown`, for every `X`. An un-evaluated alternative can only widen, so it
reaches the root **by arithmetic** rather than because someone remembered to propagate it.

`Unknown & X = X`, for every `X`. An un-evaluated conjunct can only narrow, so the other
operand is already a sound upper bound. Making `Unknown` absorbing here would be an
over-approximation so coarse it destroys every answer, and it is wrong.

Silence must never read as clean. This is the single most important correctness property here,
and `docs/ENGINEERING.md` §3 is its normative statement.

## The six AWS traps

Each silently inverts an answer, and each has a golden case with a written rationale:

1. `ForAllValues:` on a single-valued key is a **vacuous pass**. Model as `(key absent) ∨ (∀v ∈ key. v ∈ set)`.
2. `IfExists` rewrites `C(k)` to `absent(k) ∨ C(k)`.
3. `Null` polarity — `{"Null": {"k": "true"}}` means *k must be absent*, and the value is the **string** `"true"`.
4. **Duplicate condition keys** — the Terraform AWS provider collapses them before AWS sees the policy. Detect at the token level; `json.Unmarshal` destroys the evidence.
5. Condition **keys** are case-insensitive; `StringEquals` **values** are case-sensitive.
6. Policy variables make the admitted set a function of the requester. A symbolic hole, never a literal.

Plus two facts that are not traps but are load-bearing: `aud` is **not** an authorization boundary
(`configure-aws-credentials` sets `aud=sts.amazonaws.com` for every AWS customer on earth), and
`StringLike`'s `*` matches `/` and `:` — so `repo:acme*` admits `repo:acme-evil/x` while
`repo:acme/*` does not. One character, and it is the highest-frequency real bug in this space.

## Evidence

Collectors do IO and emit `Evidence`. Evaluators are pure functions over `Evidence`. Nothing else
crosses that line.

`Status` carries `denied` as a value because a permission denial is a fact, not an absence. The
tri-state resolver below cannot work without it.

## The resolver

GitHub returns **404 for both** "does not exist" and "exists but is private and you cannot see it".
Reporting "deleted" on a 404 is wrong about a third of the time, in exactly the vendor and
contractor cases that matter most.

```
Exists        { Public, Archived, Fork, PushedAt }
Claimable     { Basis, Evidence }     // the namespace is genuinely free
Occupied      { ByOwnerID, Evidence } // exists, different owner -- a rename or transfer
Indeterminate { Reason, Evidence }    // 404 under this credential; cannot distinguish
```

Resolution order, cheapest first, public metadata only:

1. **Owner before repo.** `GET /orgs/{owner}` also 404 → the whole namespace is gone.
2. **Their credential, not ours.** The CLI runs with the customer's own `gh` auth.
3. **Numeric owner IDs, not names.** A different owner ID means `Occupied`.
4. **GitHub's retirement rule.** >100 clones or Actions uses in the prior week → the namespace is permanently retired and not claimable.

`Indeterminate` is a first-class result carrying the calls made, the responses received, and the
flag that would resolve it. It is the credibility mechanism, not a limitation being disclosed.

### Network invariant

> CloudArq issues unauthenticated GETs **only** to a small, hard-coded allow-list of code-hosting
> providers. It **never** issues a request to any host derived from customer configuration.

An FIC `issuer`, a WIF `oidcIssuerUri` and an OIDC provider `Url` are attacker-controlled strings
in the customer's configuration. Fetching one is both a request at third-party infrastructure and
an SSRF gadget running inside the customer's network. The legal and security constraints agree
exactly, which is why the issuer registry is **embedded data, never a live fetch**.

## Why new facts are data

A new issuer, claim key or subject grammar must be addable by editing `registry/issuers.yaml` and
nothing else. If it requires a code change, the abstraction is wrong.

Competitors hardcode issuer hostnames in source. Every new issuer costs them a release; it costs
us a line of YAML shipped by CI the same day. The domain produces new facts roughly monthly, so
that asymmetry compounds.
