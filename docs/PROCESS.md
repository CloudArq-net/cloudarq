# Engineering process

This describes how work gets done here. It applies to every contributor without exception.

The repository is the credential. Everything in it is read as a statement about how we work,
so the process is written down rather than assumed.

---

## Roles

| Role | Held by | Owns |
|---|---|---|
| **Product** | Abdallah Khaldi | What gets built, why, and in what order. Accepts or rejects work. |
| **Architect** | Whoever is implementing | *How* it gets built. **Owns the right to say no to a brief.** |
| **Implementation, QA, Review, Release** | Same person, separate passes | See below. |

The last row is the important one. On a small team these roles collapse into one person, and
when they collapse they stop working — the author becomes the reviewer of their own assumptions,
and the tests get written to agree with the code. **So they are run as separate passes, in
order, with separate outputs.** A pass that produces no artifact did not happen.

---

## How work enters

1. Product writes a spec in `specs/`, in the format `specs/README.md` defines.
2. Architect reads it and either accepts it or pushes back. **Pushing back is expected.** A brief
   that is wrong, ambiguous, or unsafe gets rejected before a line is written, not silently
   reinterpreted halfway through.
3. The five passes run.
4. `make check` goes green.
5. One commit, with a message that explains *why*.

Nothing merges red. There is no "fix it in the next commit."

---

## The five passes

### Pass 1 — Architect

Before writing any code, produce:

- **The goal restated in one sentence.** If you cannot, you have not understood the brief.
- **The exact list of files you will create or modify.** This becomes the scope contract.
- **The three things most likely to go wrong**, named specifically. Not "bugs" — "the term cap
  could truncate instead of widen, which would under-report."
- **Every place the spec is ambiguous, wrong, or unsafe.** If there is one, stop and say so.
  Do not choose an interpretation and proceed.

### Pass 2 — Implementation

Write the whole thing.

- No stubs. No `TODO` in shipped code. No `panic("not implemented")`.
- No "simplified for brevity", no "in a real implementation you would". If the brief says
  implement it, implement it. If it is too large, say so in Pass 1, not by shipping half.
- Errors are handled or returned. Never `_ = err`. Never a bare `recover()` that swallows.
- Doc comments explain **why**, not what. `// increment i` is noise; `// the digest deliberately
  excludes FetchedAt so identical responses hash identically` is the reason someone will need
  in a year.

### Pass 3 — QA

Write tests that try to **break** the implementation, not tests that confirm it.

**The red run is mandatory and is the output of this pass.** Move the implementation aside, run
the suite, and capture the failure. Paste it.

```
git stash push -- internal/eval/stringset.go
go test ./internal/eval/...     # must be RED
git stash pop
go test ./internal/eval/...     # must be GREEN
```

A test suite that has never been observed failing is not a test suite. It is a set of
statements that happen to be true about whatever the code currently does.

Every behavioural change ships with a test that fails on the pre-change code. No exceptions,
and "it's obviously correct" is not one.

### Pass 4 — Review

Adversarial, and done in this order:

1. Read the **Semantics** section of the spec.
2. *Then* read the code.
3. Try to find one case where they disagree.

Reading the code first makes you agree with it. The order is not a suggestion.

Hunt specifically for the failures that recur in this codebase:

- **Absent versus empty.** A missing claim is unconstrained, not rejected. Getting this
  backwards inverts a finding.
- **Inference from absence.** A check that produced no output is not a check that passed.
- **Under-approximation.** Anywhere a set could be reported *smaller* than reality. This is the
  one that ends the company: a dangerous policy reported as admitting nobody.
- **Non-determinism.** Map iteration in output. `time.Now()`. Unsorted anything.
- **Swallowed errors.** A denial reported as an absence.
- **Vacuous guards.** A test whose filter matches nothing still passes.

### Pass 5 — Release

- `make check` — green, and **read the counts**. A gate that examined zero things is not a gate.
- **Scope check.** `git status --porcelain` must be a subset of the file list from Pass 1.
  Anything else is either a mistake or a decision that needed saying out loud.
- **Forbidden-string check.** See Authorship in `ENGINEERING.md`.
- Commit message: what changed, and **why it is correct**. Not a diff summary — the diff is
  already in the diff.

---

## Definition of done

All of these, mechanically:

- [ ] `make check` prints `all checks green`
- [ ] Every gate reported a non-zero count of things examined
- [ ] The red run was captured and pasted
- [ ] Changed files are a subset of the Pass-1 list
- [ ] No `TODO`, `FIXME`, `XXX`, or stub in the diff
- [ ] Every new exported symbol has a doc comment saying why it exists
- [ ] The commit message explains the reasoning, not the changes

"I believe this is correct" is not on the list. Belief is not an artifact.

---

## No shortcuts

There is no time budget and no token budget. The only currency is correctness.

**Banned outright:**

- Weakening, skipping or deleting a test to make a gate pass. If a test is wrong, say it is
  wrong and argue why. Then change it in its own commit, with reasoning.
- Lowering a coverage threshold.
- Adding a special case to make one test pass.
- Fabricated content of any kind: invented testimonials, placeholder metrics presented as real,
  example customers, made-up benchmark numbers, fake names. If a value is not measured, it does
  not appear. **This applies to marketing copy exactly as much as to code.**
- Declaring completion without running the gates.
- Silently reinterpreting a brief.

**Also banned, and easy to miss:** claiming a check passed when the check errored. A script that
fails to run and still prints "clean" is worse than no script, because it manufactures false
confidence. Distinguish *ran and passed* from *failed to run*, every time.

---

## Dependencies

Adding one is a decision, not a convenience.

Before adding any dependency, state: **licence · transitive dependency count · last release
date · what breaks if it is abandoned · why the standard library will not do.**

- Permissive licences only — MIT, BSD, Apache-2.0. **No GPL, AGPL, or BSL**, ever, in anything
  we ship. Our CLI is Apache-2.0 and copyleft would poison it.
- Prefer zero transitive dependencies.
- Anything not named in the spec requires approval first. Do not add and mention it later.
- Vendored data (test corpora, fixtures) must record where it came from, its licence, and the
  date it was captured.

---

## When to stop and ask

Stop. Do not guess. Three triggers:

1. **The brief is ambiguous on something that changes behaviour.** Not style — behaviour.
2. **The brief appears wrong.** Say what you think is wrong and why, and propose the correction.
   Do not implement around it silently.
3. **The correct implementation needs something not in scope** — a new dependency, a change to a
   file outside the list, a schema change.

Asking costs a message. Guessing costs a wrong answer shipped in a product whose entire claim is
being right where others are wrong.

---

## Surface standards

Every surface is finished to the same bar. "Internal" is not an excuse; the admin console is
the one a compromised session would attack first.

**CLI** — aligned columns, scannable in two seconds. Colour only for severity, severity only
when earned. `--explain` prints every API call before making it. `--offline` is the default on
first run. Exit codes are documented and stable. The JSON schema is a public API: versioned,
with a written deprecation policy.

**Web explorer** — re-evaluates in under 16ms for a 50-statement policy, measured in CI on a
throttled runner. No account, no cookie, no storage, no telemetry beyond a first-party counter.
All state in the URL fragment so a link reproduces an analysis exactly.

**Control plane** — ingest is idempotent by content hash. It holds no cloud credential, ever.
Row-level security with `FORCE` on every tenant table from the day the table is created, proven
by a nightly cross-tenant canary rather than by review.

**Admin** — a separate application on a separate origin with **no public inbound route**,
reached only through a tunnel and a hardware-backed passkey. No `/admin` path on the customer
app. No impersonation feature, ever — it is the highest-risk capability in any SaaS and not
building it removes the risk permanently instead of defending it forever. Destructive actions
schedule rather than execute, with a cancellation window and immediate notification. The audit
log is append-only and hash-chained, and its head is published somewhere we do not control, so
tampering is detectable even if the server is fully compromised.

**Errors, everywhere** — say what went wrong and how to fix it. No apologies, no vagueness, no
error codes without text. An empty state teaches: *"no external principals found — here are the
14 calls made, and the 2 that were denied."*

---

## Two people, one working tree

More than one contributor may have the repository open at once. The tree is shared state and
`git` has no locking, so the discipline is ownership, not politeness.

**Ownership while a task is in flight**

| Path | Owner |
|---|---|
| `cmd/`, `internal/`, `test/`, `go.mod`, `go.sum` | whoever holds the current spec |
| `specs/`, `LOG.md`, `docs/` | whoever is writing process or briefs |

**Rules, in order of how badly breaking them hurts**

1. **Never run a tree-mutating git command on work you do not own.** `stash`, `checkout`,
   `reset`, `clean`, `rebase`, `restore`, and `commit --amend` all silently move or delete
   someone else's uncommitted files. There is no undo for `stash` that fails to pop.
2. **Never `git add -A` while another task is in flight.** Stage the paths you own, by name.
   A blanket add sweeps the other contributor's half-finished work into your commit.
3. **Read `git status` before you stage anything.** If it shows files you do not own, leave
   them alone and say so.
4. **Read-only is always safe.** `log`, `diff`, `show`, `status`, `ls-files` never mutate.

If you need the tree clean and it is not — because a test needs an isolated state, say — do not
stash. Ask, or copy the repository elsewhere and work there.

---

## The log

Every session appends to `LOG.md` before it ends. One block per unit of work: what was done, why,
the artifacts, the command that verified it, and what is left open.

**Mistakes get a block of their own, in the same format, unsoftened.** A log that records only
what went well is a marketing document. Its value appears three weeks later when something breaks
and the question is what changed — and by then the entry either exists or it does not.

"Verified" means a command was run and its output observed. It does not mean the change looked
correct.

---

## Named anti-patterns

So they can be called out by name in review.

| Name | What it is |
|---|---|
| **Vacuous pass** | A check that examined nothing and reported success. |
| **Absence as evidence** | Concluding a pass because no failure was printed. |
| **Agreeable test** | A test written after the code, asserting what the code does. |
| **Silent reinterpretation** | Deciding the brief meant something else and not saying so. |
| **Under-approximation** | Reporting a set smaller than reality. The worst class of bug here. |
| **Confidence theatre** | "Done", "verified", "should work" with no artifact behind it. |
| **Scope drift** | Touching a file the brief did not name. |
