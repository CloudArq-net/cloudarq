# 07 — a construct the parser does not model, said out loud twice

**The document.** `ForAllValues:StringLike` on `sub`, which passes when the claim is absent.

**What the golden pins.**

- `sub` renders as `?("ForAllValues:StringLike")` and its words are `not evaluated · note 1`.
  The note number is the answer's own numbering, the same number the explorer prints, so a
  reader moving between the two surfaces follows one set of numbers.
- Both notes: the caveat, which is what makes the set an upper bound, and the anomaly, which
  is the record that the construct was seen. They carry the same message and different
  provenance lines, and the command prints both rather than folding them together: they are
  two facts, and which one the reader needs depends on what they are checking.
- The caption *The set shown is an upper bound, not the set*. `docs/ENGINEERING.md` section 3
  requires that a renderer never print a clean answer over an inexact result; this line and
  the `so the set shown is an upper bound` clause in the sentence are how the command does
  it, and both come from the answer.
- The witness caption naming `sub` as not shown *because it was not evaluated* — not as
  unconstrained, which would be a stronger claim than the engine made.

**Why this is the right answer.** `ForAllValues` over a claim a token may omit does not
restrict what it appears to restrict. The engine declines to evaluate it, and the command's
job is to make the decline visible in every place a reader might otherwise take silence for
a clean answer.
