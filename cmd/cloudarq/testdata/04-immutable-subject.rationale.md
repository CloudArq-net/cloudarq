# 04 — an immutable subject: a long value printed whole

**The document.** One `StringEquals` on a subject that carries both numeric ids:
`repo:acme@123456/infra@456789:ref:refs/heads/main`.

**What the golden pins.** The value appears three times — in the sentence, in the `ADMITS`
column and in the witness — and it is 49 characters in all three. Nothing is cut, nothing is
abbreviated and no ellipsis appears anywhere. A truncated value is a wrong value: a reader
who cannot see where the subject ends cannot tell `repo:acme@123456/…` from
`repo:acme@1234567/…`, which are different organisations.

**Why this is the right answer.** The line runs past eighty columns, and that is the correct
outcome: the width of the terminal the answer is read in is not an input to the answer, so
the command neither wraps nor truncates, and the same bytes are printed wherever it runs.
