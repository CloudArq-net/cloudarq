# 01 — one repository, one branch: the plainest answer the command gives

**The document.** `testdata/grants/01-one-repo-one-branch/aws.json`: one statement, one
federated principal, two condition keys under `StringEquals`.

**What the golden pins.**

- The document line, which says how the bytes were read and not what they are. Nothing in
  the reading establishes that a document *is* an AWS trust policy — this command reads
  every document as one, because it reads no other dialect yet — so `read as an aws trust
  policy` is a statement about this run, which is the only thing there is evidence for.
- The digest on the line under it. It is printed whole, not shortened: it is what
  `shasum -a 256` of the file prints, so it can be compared with it.
- The grant head: which statement the grant came from, its `Sid`, the effect and the issuer.
- The sentence and the caption, taken from the answer verbatim. They are the same strings the
  explorer prints; `cmd/cloudarq/01-one-repo-one-branch.json` beside this file is the same
  answer in the public schema, and the two goldens move together or one of them is wrong.
- A three-column table whose widths come from the longest cell in each column and from
  nothing else. `sub`'s rendered value is the widest cell in `ADMITS`, and the third column
  starts two spaces after it.
- The last row, `any other claim  any  unconstrained · no condition names it`, which the
  page appends to every term and the command now appends too. The two claims above it are
  the ones the document constrains; without the row the table reads as the list of claims
  that matter, and a reader would take a claim absent from it to be excluded.
- A witness: the decoded payload of a token this grant admits, indented under the engine's
  own heading and followed by the engine's own caption.
- The evidence line: where the statement is written and the digest of those bytes.

**Why this is the right answer.** Both claims are exact, nothing went unevaluated, and the
set is a single term, so the sentence states it without a caveat and the caption says only
what the command did not do — resolve who holds those identities. A reader can take the
offset and the digest on the last line back to the file and quote the statement themselves.
