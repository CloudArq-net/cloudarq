# 07 — a construct the parser does not model, said out loud twice

**The document.** `ForAllValues:StringLike` on `sub`, which passes when the claim is absent.

**What the golden pins.**

- `sub` renders as `?("ForAllValues:StringLike")` and its words are `not evaluated · note 1`.
  The note number is the answer's own numbering, the same number the JSON carries, so a
  reader moving between the text and the JSON follows one set of numbers.
- Both notes: the caveat, which is what makes the set an upper bound, and the anomaly, which
  is the record that the construct was seen. They are two facts with one message, so the text
  prints the message once, under note 1, and note 2 reads `same as note 1` above its own
  provenance line. Each keeps its number, which is the number the JSON gives it, and the JSON
  carries the message in both.
- The caption *The set shown is an upper bound, not the set*. A renderer must never print a
  clean answer over an inexact result; this line and
  the `so the set shown is an upper bound` clause in the sentence are how the command does
  it, and both come from the answer.
- The witness caption naming `sub` as not shown *because it was not evaluated* — not as
  unconstrained, which would be a stronger claim than the engine made.

**Why this is the right answer.** `ForAllValues` over a claim a token may omit does not
restrict what it appears to restrict. The engine declines to evaluate it, and the command's
job is to make the decline visible in every place a reader might otherwise take silence for
a clean answer.
