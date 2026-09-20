# escapes — a document that tries to rewrite the terminal it is printed on

**The document.** `internal/report/testdata/escapes.json`: an ESC and a BEL in a `Sid`, an
ESC inside a claim value, an ESC inside a condition key, and an ESC inside an operator's
name. Every byte of it is valid JSON — the escapes are written `\u001b`, which is how a
policy carrying one arrives from a console, a template or Terraform.

**What the golden pins.**

- `Erase[2KThisLine` in the head and on the evidence line: the ESC and the BEL are gone and
  the rest of the Sid is intact. `\x1b[2K` erases the line a terminal is on, which is how a
  grant that admits everyone could be made to leave no trace on the screen.
- `runner[1menvironment` as a claim name, and the sentence carrying the same stripped text as
  the spans. The page renders the spans and the command renders the sentence; if the
  stripping happened in only one of them the two surfaces would print different words for
  the same grant, which is what `TestTheSentenceIsExactlyItsSpans` forbids.
- The `ADMITS` column showing `"repo:acme/\x1b[31minfra:…"`: the engine's canonical rendering
  quotes the value, so the escape is already six printable characters there and stays. The
  same is true of `\u001b` in the witness, which is JSON. Neither is a control byte, and
  `TestNoControlCharacterLeavesTheText` is the assertion that none reaches the output.
- The column widths, measured on the stripped text: the second column starts two spaces after
  `runner[1menvironment`, twenty characters, not twenty-one.
- Grant 2's table, which has one row and names no claim. The operator was not modelled, so
  the term constrains nothing, and the answer's term is empty; the row that survives says
  every claim is unconstrained, which is exactly what such a grant admits. Printed as
  nothing at all — as it was — the caption above it referred to a set the reader was never
  shown.

**Why this is the right answer.** `docs/ENGINEERING.md` section 9 states the consequence of
getting this wrong — terminal escapes in a tag can rewrite CLI output, including making a
dangerous finding look clean. The stripping is done where the answer becomes text, so that
the JSON surface, which escapes them safely, keeps carrying the document as written.
