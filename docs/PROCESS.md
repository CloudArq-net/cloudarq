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

**The red run is mandatory and is the output of this pass.**

A test suite that has never been observed failing is not a test suite. It is a set of
statements that happen to be true about whatever the code currently does.

**Removing the implementation does not count.** It produces a build failure, which proves only
that the tests reference the symbols. It tells you nothing about whether any individual test
would catch a *wrong* implementation, which is the only thing worth knowing. Absence of the
code is not evidence about the tests. This is the `absence as evidence` anti-pattern wearing a
different hat, and the earlier wording of this section committed it.

**The red run is a mutation run.** Copy the package to a scratch directory outside the tree.
Make the implementation *wrong* — one deliberate defect at a time — and record which test fires
first. Restore. Repeat.

```
cp -r internal/eval "$SCRATCH/eval-mutant"
# edit ONE thing to be wrong, e.g. make Unknown absorbing under Meet
go test ./...              # must be RED, and you must name which test caught it
```

At minimum, one mutation per class of defect the unit can have. For a lattice that is:
under-approximation, matcher, normalisation, lattice law, determinism, rendering — and one
**guard on the guard**, a mutation to the *generator* that makes it stop producing the
interesting case, to prove the test would notice its own inputs going stale.

Every mutation must be caught, and the report names the mutation, its class, and the first two
tests that fired. A mutation nothing catches is a missing test, not an acceptable gap.

Keep a green control copy alongside and run it in the same session, so a mutation "caught" by
an unrelated broken build is visible as such.

Every behavioural change also ships with a test that fails on the pre-change code.

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
- [ ] The mutation run was captured and pasted: every class mutated, every mutation caught,
      each named with the first two tests that fired
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

## The craft standard

The target is not "working". It is code a senior engineer would read on a Monday morning and
have nothing to say about. Every layer: engine, CLI, API, schema, frontend, build, docs.

### Elegant, which is not the same as short

Three failure modes, and the middle one is the target.

- **Under-written.** Cleverness compressed until it is unreadable. One-letter names, nested
  ternaries, a regex where a parser belongs, a function that does four things because splitting
  it would have cost two more lines. Golfed code is not elegant code.
- **Over-written.** An interface with one implementation. A factory that constructs one thing.
  A config option nobody sets. Four layers of indirection between the caller and the work.
  Abstraction added for a second case that has not arrived and may never.
- **Elegant.** The shape of the code matches the shape of the problem. A reader who understands
  the domain can predict what the next function is called before scrolling to it. Nothing is
  there for a future that has not happened, and nothing is missing that the present needs.

The test: **could you delete anything without losing meaning, and could you add anything
without gaining any?** If the answer to either is yes, it is not finished.

### Helpers, and where the line is

Extract a helper when the extracted thing **has a name** — when there is a concept underneath
that deserves to be said out loud. `normaliseGlob`, `admitsEmptySet`, `isVacuousCondition`.
Those are helpers. `doStep2` is not; it is a line count with a function wrapper.

**Do not repeat yourself, and do not abstract away two things that merely look alike.** Two
blocks with the same shape and different reasons for existing are two blocks. Merging them
creates a helper that must grow a boolean parameter the first time the reasons diverge, and a
boolean parameter is a merged helper apologising for itself.

Three strikes before a generic abstraction, and the third must actually be a third *case*, not
a third *instance* of the first.

### Naming

Names say what a thing **is**, in the domain's words, not what it does mechanically or where
it sits. `AdmittedSet` not `ResultWrapper`. `Indeterminate` not `Status3`. A name that needs
a comment to explain it is the wrong name; fix the name, delete the comment.

Comments explain **why**, never what. The what is the code. A comment that restates the line
below it is noise, and noise is a maintenance cost forever.

### Error handling

Errors carry the context needed to act on them. An error that reaches a user says what was
being attempted, what happened, and what they can do. `fmt.Errorf("parse trust policy for role
%s: %w", arn, err)` — never a bare `return err` that arrives at the top having lost its story.

### The frontend is held to the same bar

"It looks fine" is not a standard. No arbitrary pixel values where a token exists; no component
that only works at one width; no animation without a `prefers-reduced-motion` path; no colour
pair that has not been contrast-measured; no interactive element without a keyboard path and a
focus ring. The design tokens are the single source of truth and a hex literal outside them is
a bug.

### NO AI SLOP

This is a hard rule and it is not about tone.

**Banned:** filler prose that says nothing; symmetrical bullet lists padded to look complete;
a README written before the thing works; hedging language around a claim that is either true or
false; "comprehensive", "robust", "seamless", "leverage", "delve" and their family; emoji
section headers; a comment on every line; `// TODO: improve this`; tables with a column added
for balance; summaries that restate what the reader just read.

**Also banned, and this is the one that actually matters:** any sentence asserting something
that was not checked. If a number is not measured, it does not appear. If a claim is not
verified, it is not stated. If a test was not run, it did not pass. Confidence without evidence
is the most expensive form of slop because it is the one that ships.

Write the way a good engineer writes a commit message to a colleague they respect: short,
specific, load-bearing, and no sentence that could be deleted without loss.

---

## The department

You are the architect. Behave as though you have a team and the team reports to you.

On every unit of work, all of these happen, and they are separate acts even though one agent
performs them:

- **Architecture.** What is the shape, what are the boundaries, what could be wrong later.
- **Implementation.** The code.
- **QA.** Adversarial, against the *spec*, not against the implementation's intent. QA's job is
  to find the case the implementer did not consider, and QA is not satisfied by "the tests pass".
- **Review.** Semantics read first, code second, looking for one place they disagree. Use a
  fresh agent that has not seen the implementation reasoning where the unit is non-trivial.
- **Release.** Gates, coverage, determinism, purity, preflight, log.

Use as much capability as the problem needs. **There is no token budget and no time budget.**
Spawn subagents for review and for adversarial QA. Run things twice. Read the upstream source
rather than assuming its behaviour. The only currency is correctness.

Where you disagree with a brief, say so in Pass 1 and argue it. **You hold the right to refuse
a brief you believe is wrong.** Silent compliance with a bad instruction is the failure mode
this process exists to prevent.

---

## Autonomy

**Commit and push without asking.** Every push runs `scripts/preflight.sh`, which is the gate;
if preflight passes and the definition of done is met, push. Do not queue work waiting for a
human to say yes to something the gates already answered.

Push in coherent increments — one unit of work, one commit, message explaining the reasoning.
Do not batch a day's work into one commit, and do not push a half-finished unit to "save
progress"; that is what the local tree is for.

**Stop and ask only for the four things in `When to stop and ask`, plus:**

- Rewriting published history, or any force-push.
- Deleting or renaming something outside the current unit's file list.
- Adding a dependency (see `Dependencies` — the licence rule is absolute).
- A change to `docs/PROCESS.md`, `docs/ENGINEERING.md`, or `CLAUDE.md`. Those are the Product
  owner's files. Propose the edit and the reasoning; do not apply it.
- Anything that touches billing, auth, or customer data handling.

Everything else is yours. Being blocked on a question nobody needed to answer is a failure of
judgement, not an abundance of caution.

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
