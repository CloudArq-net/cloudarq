# 02 — one repository, any branch: a pattern, and the simplest token that matches it

**The document.** One statement; `sub` is constrained with `StringLike` to
`repo:acme/infra:*`.

**What the golden pins.**

- `matches` rather than `is` in the sentence, and `like:"repo:acme/infra:*"` in the `ADMITS`
  column: the column prints the engine's canonical rendering of the set, which is what
  finding identifiers are addressed on, and the words column says the same thing in English.
- The witness `"sub": "repo:acme/infra:"` — the pattern with its star removed, which is the
  simplest value the constraint admits. The engine builds it and confirms it against the set
  before offering it; the command prints it and adds nothing.

**Why this is the right answer.** A branch is not named, so every ref and every environment
of that one repository is admitted. The sentence says the boundary that exists — the
repository — and the witness makes it concrete rather than describing it.
