# escapes.json — the one document in the corpus that carries a terminal escape

**Why this fixture exists.** Every document under `testdata/` is well behaved. Measured over
the 31 documents the package's `corpus` loads — 24 policies and 7 grant corpora — the sids,
sentences, claim names, rendered values and witnesses of every grant carry **0** control
characters between them. The stripping rules in `words.go` and `text.go` would therefore be
asserted over text that never had one in it — a vacuous pass, and the gate would examine
nothing. This document is the input that makes them examine something.

**Where the escapes are, and why each one is there.** The four places a document can carry a
control character are the four places customer configuration reaches the rendering.

| Where | Bytes | Why that place |
|---|---|---|
| `Sid` of statement 0 | `[2K` and `` | The Sid is printed in the grant's head, in the evidence line and in the document's statement list. `ESC [ 2K` erases the line the terminal is on: a grant that admits everyone could scroll past leaving nothing on the screen. The BEL is the second control byte the fixture's own guard counts, so a strip that handled only ESC would still fail. |
| `sub` value | `[31m` | A claim value is the string the sentence quotes, and the sentence is the product. |
| condition key `runner[1menvironment` | `[1m` | A claim *name* is a table heading and a column width. An escape here moves a column as well as painting it, which is how a stripped value and an unstripped name would still line up wrongly. |
| operator `String[7mLike` | `[7m` | An operator name reaches the answer through the note that says the construct was not modelled, so the notes are covered too. `ESC [ 7m` reverses the foreground and background, the sequence that most directly makes one line look like another. |

Every escape is written ``, which is valid JSON and is how a policy carrying one
actually arrives — from a console paste, a Terraform template, or a tag copied out of another
system. A fixture written with a raw `0x1b` byte would be a fixture no generator produces.

**What is deliberately *not* here.** No escape in `Version`, `Effect`, `Action` or
`Principal`: those are values the engine matches against a fixed vocabulary, so a document
carrying an escape in one of them is refused or answered `Unknown` before the rendering is
reached, and asserting stripping on them would assert the wrong layer.

**What this fixture does not reach, and what does.** Its Unknown grant has one empty term, so
no claim name of this document reaches the witness caption — the one sentence in `words.go`
that interpolates a claim name, and the sentence a raw escape leaked through until
2026-09-20. The shape that reaches it is an unevaluated claim *inside* a term that names
other claims, which no document here has; `unknownInATerm` in `text_test.go` is that shape,
and `TestTheUnknownClaimFixtureIsWhatItClaims` is its guard. It lives in the test file rather
than beside this one because it is the input to one rule, not a document a reader would
recognise.

**What would make this fixture stale.** If someone removed the escapes to make an output
"cleaner", `TestTheEscapeFixtureCarriesEscapes` fails with `the fixture's answer carries no
control character outside its spans; the renderer below would be proving nothing` — the guard
on the guard. The fixture may grow; it may not shrink.

**Source.** Hand-written for this repository, 2026-09-20. It describes no real account, role
or repository: `acme` is the placeholder used throughout `testdata/`.
