# CloudArq — engineering rules

CloudArq turns a cloud trust policy into the list of who it actually lets in.

Read this before writing code. These rules exist because breaking them has a specific,
known cost — each one names it. When a rule and a convenience collide, the rule wins.

---

## Authorship — read this first

Commits, pull requests, tags and release notes carry **no co-author trailers and no tool
attribution**. Every commit is authored by a human, full stop. This is not a style preference:
the repository is the credential, and the reader judges it accordingly.

A `commit-msg` hook enforces this locally. It is not tracked, so set it up on any new clone:

```
cp scripts/commit-msg .git/hooks/commit-msg && chmod +x .git/hooks/commit-msg
```

---

## 0. The one idea

Every finding is one computation: **the set of principals a condition ADMITS, minus the
set you INTENDED.** A set difference, not a rule match.

This is not stylistic. A rule encodes a *format*; a set encodes *admission*. Formats change
— GitHub changed its subject grammar in July 2026, AWS added five condition keys in February
— and every rule-matching tool in this space is currently broken because of it. A lattice is
not.

**If you find yourself writing a regex against a `sub` claim, stop. You are building the
thing we exist to replace.**

---

## 1. Layout, and the one boundary that matters

```
cmd/cloudarq/          CLI entry. Flags, output, exit codes. No logic.
internal/
  eval/                PURE. The lattice. No IO, no clock, no randomness, no network.
  parse/{aws,azure,gcp}  PURE. Dialect text -> AST -> AdmittedSet.
  evidence/            The Evidence record and its Status enum.
  collect/{aws,...}    IO ONLY. Calls cloud APIs, emits Evidence. No evaluation.
  resolve/             IO ONLY. Counterparty state. Allow-listed hosts only.
  registry/            Embedded issuer data (go:embed). Data, never live fetch.
  report/              Rendering. Terminal, JSON, HTML.
web/                   WASM explorer.
testdata/golden/       Golden corpus. Every case has a rationale file.
testdata/subvectors/   Vendored CC0 conformance vectors.
registry/issuers.yaml  The published registry source.
```

**`internal/eval` and `internal/parse` must not import anything that does IO.** There is a
CI test that walks their import graphs and fails on `net`, `os`, `time`, `math/rand`, or any
cloud SDK. Cost of breaking it: the evaluator stops being testable, fuzzable and deterministic,
and you will not notice for six weeks.

Collectors produce `Evidence`. Evaluators are pure functions over `Evidence`. Nothing else
crosses that line.

---

## 2. Determinism is a product feature, not hygiene

Byte-identical output for identical input. We advertise "commit the findings file and diff
it in CI." That promise is load-bearing.

- **Never range over a map to produce output.** Sort keys explicitly. `go vet` won't catch it.
- **One injected `Clock`.** No `time.Now()` outside the injection point. `FetchedAt` is
  recorded but is **never** part of any hash.
- **Content-addressed finding IDs**: `sha256(rule, resource_urn, canonical_condition)`.
- **Canonical JSON** for anything hashed: sorted keys, no HTML escaping, stable number format.
- `TestDeterminism` runs N=20 in-process **and** in fresh subprocesses, and compares bytes.

Go randomises map iteration deliberately. A bug from this appears about one run in forty and
surfaces long after the commit that caused it.

---

## 3. `Unknown` is the top element. This is the safety property.

`StringSet` is `Exact | Glob | Any | None | Unknown`. `Unknown` means *a constraint existed and
could not be evaluated*, so the claim is unconstrained as far as we can prove.

**Absorbing under `Join`.** `Unknown ∨ X = Unknown`, for every `X`. `Join` is the union between
statements and between the values of one condition; an un-evaluated branch could admit
anything, so the union could admit anything.

**Identity under `Meet`.** `Unknown ∧ X = X`, for every `X`. `Meet` is the intersection between
conditions in the same statement; an un-evaluated AND-constraint can only ever *narrow* the
set, so the other operand stays a sound upper bound. Treating it as `Unknown` would be
over-conservative, and a tool that reports everything as unknown gets uninstalled — which is a
correctness failure with extra steps.

Inexactness is therefore **not** carried by the lattice. It is recorded per-result on the
`AdmittedSet`, by the parser, which is the only layer that knows *why* a constraint could not
be evaluated.

Silence must never read as clean. Four layers enforce it, and all four stay:

1. Any unmodeled construct sets `Exact = false` on the result and attaches a caveat naming it.
2. The renderer refuses to print a clean verdict on an inexact result.
3. The control plane returns 422 on a payload claiming `exact` while carrying caveats —
   checked by a different process than the one that computed it.
4. Severity is computed twice by independent paths; the worse result is reported.

`IsEmpty()` returns true only when emptiness is **proven**. Whenever it cannot be decided it
returns false. Getting this backwards makes the tool report a dangerous policy as admitting
nothing, which is the worst output this program can produce.

## 4. Evidence or it didn't happen

```go
type Evidence struct {
    API       string
    Params    string          // canonical JSON, sorted keys
    Status    Status          // ok | denied | throttled | unsupported | not_configured
    Bytes     json.RawMessage // verbatim. NEVER re-marshalled.
    SHA256    [32]byte
    FetchedAt time.Time       // not part of any hash
}
```

- `Status` carries `denied` **as a value**. A permission denial is a fact, not an absence.
  A tool that reports "no external principals" because a call was refused is worse than one
  that reports nothing.
- `Bytes` is stored verbatim. Re-marshalling destroys evidence — notably duplicate condition
  keys, which the Terraform AWS provider collapses before AWS ever sees the policy.
- **Every finding must be able to produce the API response that proves it.** If a claim can't
  produce its evidence, it's a bug, not a finding.

---

## 5. The counterparty resolver: tri-state, never guess

GitHub returns **404 for both** "does not exist" and "exists but is private and you can't see
it." Reporting "deleted!" on a 404 is wrong about a third of the time, and those are exactly
the vendor and contractor cases that matter.

```go
type Exists        struct{ Public, Archived, Fork bool; PushedAt time.Time }
type Claimable     struct{ Basis ClaimBasis; Ev []Evidence }
type Occupied      struct{ ByOwnerID int64; Ev []Evidence }
type Indeterminate struct{ Reason string; Ev []Evidence }
```

Resolution order, cheapest first, public metadata only:
1. **Owner before repo.** `GET /orgs/{owner}` 404 too → the whole namespace is gone.
2. **Their credential, not ours.** The CLI runs with the customer's `gh` auth. Their token
   has org visibility; a 404 under it means genuinely absent.
3. **Numeric owner IDs, not names.** Resolving under a different owner ID → `Occupied`
   (a completed rename or transfer). A different finding, still real.
4. **GitHub's retirement rule.** >100 clones or Actions uses in the prior week → the namespace
   is permanently retired and not claimable.

`Indeterminate` is a first-class result with its own colour, carrying the calls made, the
responses received, and the exact flag that would resolve it. **It is the credibility
mechanism, not a limitation being disclosed.**

### Network invariant — enforced in code, not by discipline

> CloudArq issues unauthenticated GETs **only** to a small, hard-coded allow-list of
> code-hosting providers. It **never** issues a request to any host derived from customer
> configuration.

An FIC `issuer`, a WIF `oidcIssuerUri`, an OIDC provider `Url` are attacker-controlled strings
sitting in the customer's config. Fetching one is both a request at third-party infrastructure
and an SSRF gadget running inside the customer's network. The legal and security constraints
agree exactly. **This is why the issuer registry is embedded data, never a live fetch.**

Resolve first, pin the resolved IP, re-check after redirects, block link-local and IMDS ranges.

---

## 6. New facts are DATA. New facts are never CODE.

Competitors hardcode issuer hostnames in source — Prowler's `MULTI_TENANT_OIDC_ISSUER_HOSTS`
is a four-element Python set. Every new issuer costs them a release.

**A new issuer, claim key, or subject grammar must be addable by editing `registry/issuers.yaml`
and nothing else.** If adding support for a new issuer requires a code change, the abstraction
is wrong — fix the abstraction, not the issuer.

Same for claim keys: a new key is a new dimension in the lattice, not a new branch.

---

## 7. Testing

- **100% branch coverage on `internal/eval`, enforced in CI. Nowhere else.** Blanket coverage
  targets produce test theatre. The evaluator is the one place a wrong answer is silent and
  consequential.
- **Property tests (`pgregory.net/rapid`)** — two of them encode bugs already found in the wild:
  - `TestMonotonicity` — adding a constraint can never widen the admitted set.
  - `TestStatementOrderIndependence` — reordering statements can never change the result.
    (This is a real bypass found in Checkov. Encoded here, it can never happen to us.)
- **Golden corpus**: every case has a sibling `.rationale.md` explaining why the expected
  answer is correct, citing provider docs. Without the written reason a golden file becomes
  unchallengeable folklore, and the first time it disagrees with reality you will believe the
  file.
- **Permanently include the near-misses.** Google's own recommended condition and Trivy's
  documented "good" example must PASS. A tool that fails the vendor's recommendation is broken,
  however satisfying the finding looks.
- **Vendored `testdata/subvectors/`** — CC0 conformance vectors from an external project. Treat
  a disagreement as a bug in us until proven otherwise, and record the resolution either way.
- **No LocalStack.** Its free tier ended March 2026. Use `go-vcr` cassettes with redaction hooks,
  plus a weekly job that re-records and fails if the response *shape* changed.

---

## 8. The control plane (Python / FastAPI / Postgres)

- **It never holds a cloud credential.** It ingests findings JSON. This one constraint is the
  entire procurement story; there is no price at which violating it is worth it.
- **Ingest is idempotent**: `POST /v1/scans {sha256, findings}` → 201 first time, 200 with the
  same id thereafter. CI is flaky and retries; non-idempotent ingest produces duplicate scans,
  a corrupted diff, and a customer who stops trusting the changelog.
- **The watcher is keyed on the counterparty, never on the customer.** `counterparty` is a
  globally deduplicated table. Resolve each distinct counterparty once, write one `observation`,
  fan out to every subscribed tenant. Outbound volume scales with distinct counterparties, not
  customers — the hundredth customer costs nothing to watch, and fleet intelligence falls out
  of the schema instead of being bolted on.
- **The tenancy trap that creates**: `counterparty` is deliberately global, so it is the one
  table without RLS, and therefore the one place a leak could hide. The subscription join table
  carries the tenant key and the policy; the counterparty row holds no customer-identifying
  data by construction. Assert this in the nightly cross-tenant canary.
- **Postgres RLS with `FORCE`** on every tenant table, from the day the table is created.
  `set_config(..., true)` inside explicit transactions **including Celery tasks**. PgBouncer in
  transaction mode must be leak-tested. **Never SQLite in tests** — no RLS means the tenancy
  test tests nothing.
- **No regex in the control plane ever runs against a customer string.** Go's RE2 makes ReDoS a
  non-issue in the CLI; Python's backtracking engine makes it live here. Parse instead — which
  is also the product thesis.

---

## 9. Interface rules

Reference: godbolt's linked panes, jwt.io's decoder, regex101's match explanation. **Not a
security dashboard.**

- Monospace is the **substrate**, not an accent. Sans is for prose only.
- Panes, not cards. Resizable, keyboard-navigable.
- **Three semantic colours, total**: admitted-beyond-intent, exact, unknown. `Unknown` earns
  its own colour because it is a lattice element, not a soft failure.
- **One animation**: re-evaluation as you type. Nothing else moves.
- The witness is always concrete — a decoded token the deployed policy accepts, never "this
  policy is broad."
- Hairlines. Radius ≤3px. No shadows, no gradients, nothing floats.
- Every finding has its Evidence panel one click away.
- Empty states teach: "no external principals found — here are the 14 calls made, and the 2
  that were denied."
- Strip C0/C1 escapes except `\n` and `\t` from any resource tag before printing. Terminal
  escapes in tags can rewrite CLI output, including making a dangerous finding look clean.

**CI greps the CSS and fails on**: `gradient`, `blur-[`, `backdrop-filter`, `cyber-`,
`drop-shadow`. Taste under deadline pressure is unreliable; a grep is not.

**Performance budget**: the explorer re-evaluates in **under 16ms** for a 50-statement policy,
measured in CI on a throttled runner. At 100ms it feels like a form. At 16ms it feels like an
instrument, and that feeling is the product's entire argument.

---

## 10. What NOT to build

Do not build these without an explicit decision, even if they seem small:

- Azure or GCP **collectors** (parsers yes, live enumeration no — not before revenue).
- A GitHub App. The CLI uses the customer's own `gh` auth. App is year two or never.
- An impersonation / "log in as customer" feature. **Ever.**
- Any `/admin` route on the customer application.
- A dashboard, before the CI gate ships.
- Severity scores, grades, letter ratings, or a risk number.
- Anything that makes the control plane hold a cloud credential.

---

## 11. Language and output

- Findings are **questions answered**, never verdicts issued. "This role admits any repository
  in `acme-corp`, including the 41 that are public" — not "CRITICAL: publicly assumable role."
- "Secure" is a permitted adjective. "Security" is a forbidden noun.
- The JSON schema is a **public API**: versioned, documented, with a written deprecation policy.
  People will build on it, and that is the point.
- `--explain` prints every API call before making it.
- `--offline` is the default on first run.

---

## 12. Commits

- Conventional commits. Subject ≤72 chars, imperative.
- A behaviour change ships with the test that fails on the pre-fix code. No exceptions.
- Never commit a golden file without its rationale.
- Never commit a `.env`, and never add a credential-shaped column to the schema — CI greps for
  both.
