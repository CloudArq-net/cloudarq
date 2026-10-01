# How the engine works

This is a map of the code for someone reading it for the first time: what the engine computes,
how the packages divide the work, and the rules the tests hold them to.

## What it computes

A trust policy is read into **grants**. A grant says that tokens from one issuer, whose claims
satisfy some constraints, may assume the target. The constraints are held as an
**admitted set**: a union of terms, each term a conjunction of one set of values per claim.
Each per-claim set is built from five kinds of node:

| Node | Meaning |
|---|---|
| `Exact` | the claim equals one value |
| `Glob` | the claim matches a pattern, with AWS's `*` and `?` |
| `Any` | the claim is not constrained |
| `None` | no value satisfies the constraint |
| `Unknown` | a constraint exists and could not be evaluated |

`Meet` is AND, within a statement; `Join` is OR, across statements and across the values of one
condition. `Unknown` is the top of the lattice with a record of why: it absorbs under `Join`,
because an alternative that was not evaluated could admit anything, and it is the identity
under `Meet`, because a conjunct that was not evaluated could only have narrowed. So an
unevaluated constraint reaches the answer by arithmetic, and by the lattice's laws, which the
property tests check, it can only widen what is reported. The one place where Unknown has to point the other way is a Deny:
a Deny the parser cannot fully evaluate is not applied, and the answer says so.

`Contains` is exact for every set, so the lattice laws are checked by property tests.
`IsEmpty` and `IsTop` answer true only when they can prove it; whether two patterns share a
string is one of the questions they leave undecided, and undecided never reads as empty.

From the admitted set the engine builds a **witness**, a token the grant admits, and places the
grant in a **ring**: anyone at all, anyone on the issuing platform, a named outsider, your
pipelines, or your people. A grant's place is the nearest ring guaranteed to hold every
identity able to present a token it admits. Each term of the admitted set is placed on its own,
and the grant takes the outermost. The place is exact or unknown apart from whether the set is
exact: a place is exact when it follows from facts the census verified and from constraints
read exactly, and no constraint left unread could move it nearer. A condition on a key of
AWS's request context that the engine does not evaluate, `aws:SourceAccount` say, leaves a
platform place unknown, since such a key can name the account a request comes from.

## The packages

| Path | What it holds |
|---|---|
| `internal/eval` | The lattice: per-claim sets, admitted sets, `Meet`, `Join`, containment and witnesses. |
| `internal/trust` | The provider-neutral grant: issuer, effect, admitted set, and the caveats and anomalies a reader recorded. Its conformance suite writes each trust relationship in every cloud's syntax, and the AWS, Azure and Google readers must each parse it to the grant the case expects. |
| `internal/parse/aws` | AWS role trust policies into grants. The only reader the command uses. |
| `internal/parse/azure` | Microsoft Entra federated identity credentials, classic and flexible, from Microsoft Graph or Azure Resource Manager. |
| `internal/parse/gcp` | Google Cloud workload identity pool providers, their CEL attribute conditions, and the IAM policy members that bind them. |
| `internal/parse/terraform` | The JSON of `terraform show -json`, for a plan or a state, into the grants the cloud readers produce. |
| `internal/parse/casefold` | Case folding generated from Unicode 17.0.0's `CaseFolding.txt`. |
| `internal/registry` | What the engine knows about each issuer, read from the census module `github.com/CloudArq-net/issuers`. |
| `internal/ring` | The placement of each grant in a ring. |
| `internal/join` | Links between grants on two different targets that admit a common identity, read by any of the parsers. The command does not use it. |
| `internal/evidence` | The provenance record a grant carries: the call or the read that produced it, with the response verbatim and a status in which a denied call is a value. The readers build one for each document they are handed. Nothing in this repository calls a cloud API; where a comment says collector, it means a program that does. |
| `internal/report` | The answer, as JSON and as text. Every sentence of an answer is composed here. |
| `cmd/cloudarq` | The command. |
| `web/wasm` | The WebAssembly entry, built with TinyGo; `web/wasm/native` renders the same answers natively so the two builds can be compared byte for byte. |
| `web/engine` | The JavaScript loader for the WebAssembly engine, its tests, the differential against the native build, and `build.sh`, which builds the module and runs them. |
| `test/arch` | Tests of the code's structure: the pure packages' imports, the use of Unicode tables, the Go version CI installs, and the pins of the CI workflows. |
| `testdata/` | The corpus: documents, each with the answer expected of it and a rationale that quotes the vendor documentation the answer rests on. |

## Rules the tests hold

- **Nothing the engine cannot read narrows an answer.** A construct a reader does not model
  becomes `Unknown` on the claim it constrains, with a caveat and an anomaly whose sentence
  names it. In the AWS reader, a statement is never dropped, and a principal it cannot model
  still yields a grant.
- **The pure packages do no IO.** `eval`, `join`, `parse`, `registry`, `report`, `ring` and
  `trust` import none of `net`, `os`, `os/exec`, `syscall`, `golang.org/x/sys`, `bufio`,
  `database/sql`, `math/rand`, `math/rand/v2`, `crypto/rand`, `hash/maphash` or a cloud SDK,
  directly or through another package (`make purity`). The walk stops at `encoding/json`,
  `fmt`, `crypto/sha256` and `time`: they reach `os`, and do IO only on a file or connection
  they are handed, which no pure package hands them.
- **Identical input gives identical bytes.** The determinism tests compare outputs across fresh
  processes, where Go's map iteration order differs (`make determinism`).
- **Four packages have every statement covered.** `make cover` fails if a statement of `eval`,
  `trust`, `parse` or `ring` is not run by their tests.
- **Case is folded from data.** AWS compares action names and condition keys without regard to
  case and documents no folding beyond ASCII, so a letter is read as every letter Unicode's case
  folding relates it to. The tables come from `CaseFolding.txt`, not from the Go standard
  library, whose Unicode version depends on the Go release; a test in `test/arch` fails when
  the module's non-test code reads the standard library's tables.
- **Facts about issuers are data.** No issuer host name is written in the AWS reader. The claims
  that name a tenant, the forms a subject takes and the condition keys AWS documents for an
  issuer come from the census module; an issuer it does not describe gets the widest reading.
- **Input is bounded.** A policy is read up to 256 KiB and a token up to 16 KiB, well above the
  8,192 characters AWS accepts for a role trust policy.

## AWS behaviour the corpus covers

Each of these changes an answer silently when it is read wrongly, and each has a case under
`testdata/policies/` with a rationale that quotes AWS:

1. `ForAllValues:` passes when the key is absent (`05-forallvalues-vacuous`).
2. `IfExists` makes a condition pass when its key is absent (`06-ifexists-vacuous`).
3. `Null` takes the string `"true"` to mean the key must be absent (`07-null-polarity`).
4. A condition key written twice in one operator block: a JSON decoder keeps one, and the
   deployed policy may carry either, so the engine finds the repeat in the bytes and leaves the
   claim unconstrained, with a note (`04-duplicate-condition-key`).
5. Condition keys are compared without regard to case; `StringEquals` values are not
   (`03-key-case-value-case`).
6. A policy variable makes the admitted set depend on the caller, so it is not read as a fixed
   value (`10-policy-variable`); in a document without `"Version": "2012-10-17"`, AWS reads it
   as literal text, and so does the engine, with a note saying so
   (`21-variable-read-as-text`).
7. In `StringLike`, `*` matches any characters, `/` and `:` included (`08-stringlike-wildcards`).

## The WebAssembly build

`web/wasm` is the engine as a WebAssembly module. With TinyGo 0.42.0:

```sh
tinygo build -o cloudarq.wasm -target web/wasm/target.json -buildmode=c-shared \
  -scheduler=none -opt=s -no-debug -panic=trap ./web/wasm
```

`target.json` is TinyGo's `wasm` target with a 1 MiB stack, because the readers recurse once
per level of nesting. The module is a library: start it with the `wasm_exec.js` in TinyGo's
`targets` directory, whose `run` initialises it and returns. It exports `reserve`, `admits`,
`explain` and `answerAt`. A caller reserves room for its input, writes the policy's bytes, and
for `explain` the token's bytes after them, calls `admits(policyLength)` or
`explain(policyLength, tokenLength)`, and reads that many bytes from `answerAt()`. The answer is
the JSON `cloudarq admits --json` prints for the same policy and token, without `--owner`, byte
for byte but for the newline the command ends its output with.

`web/engine/engine.ts` does those steps for a caller. `loadEngine` takes a compiled module and
returns an object with `admits(policy)` and `explain(policy, token)`, each returning the JSON as
a string; it writes nothing to `globalThis`, and it replaces an instance that trapped or whose
memory grew past a bound, so the next call meets a live engine. `answer.ts` holds the types of
the JSON. `wasm_exec.js` is TinyGo 0.42.0's, vendored unchanged below a first line that records
its digest.

`web/engine/build.sh` builds the module and checks it: its size against a budget of 400,000
bytes compressed with brotli, the loader's tests, and a differential that runs the policies
under `testdata/policies` and `testdata/grants` and a set of generated documents through the
WebAssembly engine and the native one and requires the same bytes from both, for `admits` and
for `explain`. It needs TinyGo, Binaryen's `wasm-opt`, `brotli` and Node.
