# escapes.json — the one document in the corpus that carries a terminal escape

**Why this fixture exists.** Every document under `testdata/` is well behaved. Measured over
the 31 documents the package's `corpus` loads — 24 policies and 7 grant corpora — the sids,
sentences, claim names, rendered values and witnesses of every grant carry **0** control
characters between them. The stripping rules in `words.go` and `text.go` would therefore be
asserted over text that never had one in it — a vacuous pass, and the gate would examine
nothing. This document is the input that makes them examine something.

**Where the escapes are, and why each one is there.** The four places a document can carry a
control character are the four places user configuration reaches the rendering.

| Where | Bytes | Why that place |
|---|---|---|
| `Sid` of statement 0 | `\u001b[2K` and `\u0007` | The Sid is printed in the grant's head, in the evidence line and in the document's statement list. `ESC [ 2K` erases the line the terminal is on: a grant that admits everyone could scroll past leaving nothing on the screen. The BEL is the second control byte the fixture's own guard counts, so a strip that handled only ESC would still fail. |
| `sub` value | `\u001b[31m` | A claim value is the string the sentence quotes, and the sentence is the answer. |
| condition key `runner\u001b[1menvironment` | `\u001b[1m` | A claim *name* is a table heading and a column width. An escape here moves a column as well as painting it, which is how a stripped value and an unstripped name would still line up wrongly. |
| operator `String\u001b[7mLike` | `\u001b[7m` | An operator name reaches the answer through the note that says the construct was not modelled, so the notes are covered too. `ESC [ 7m` reverses the foreground and background, the sequence that most directly makes one line look like another. |

Every escape is written `\u001b`, which is valid JSON and is how a policy carrying one
actually arrives — from a console paste, a Terraform template, or a tag copied out of another
system. A fixture written with a raw `0x1b` byte would be a fixture no generator produces.

**What is deliberately *not* here.** No escape in `Version`, `Effect`, `Action` or
`Principal`: those are values the engine matches against a fixed vocabulary, so a document
carrying an escape in one of them is refused or answered `Unknown` before the rendering is
reached, and asserting stripping on them would assert the wrong layer.

**What reaches the witness caption.** The witness caption is the one sentence in `words.go`
that interpolates a claim name. The shape that reaches it is an unevaluated claim *inside* a
term that names other claims. Since the engine reads only the condition keys AWS documents for
an issuer's tokens, this fixture has that shape: `runner\u001b[1menvironment` is no key AWS
documents for GitHub, so statement 0's term holds it unevaluated beside `aud` and `sub`, and
the caption names it.
`unknownInATerm` in `text_test.go` is the same shape on a key whose operator is not modelled,
and `TestTheUnknownClaimFixtureIsWhatItClaims` is its guard; it lives in the test file because
it is the input to one rule, not a document a reader would recognise.

**What would make this fixture stale.** If someone removed the escapes to make an output
"cleaner", `TestTheEscapeFixtureCarriesEscapes` fails with `the fixture's answer carries no
control character outside its spans; the renderer below would be proving nothing` — the guard
on the guard. The fixture may grow; it may not shrink.

**Source.** Hand-written for this repository, 2026-09-20. It describes no real account, role
or repository: `acme` is the placeholder used throughout `testdata/`.
