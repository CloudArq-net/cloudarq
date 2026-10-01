# Contributing

Issues and pull requests are welcome.

## Issues

The most useful issue is a wrong answer: a policy for which `cloudarq admits` says something
AWS does not do. Please include:

- the trust policy, with account ids and organisation names replaced if they are real;
- the command line, and the output of `cloudarq version`;
- what the command printed, and what you expected;
- the AWS documentation, quoted with its URL, that says how AWS reads the policy.

A crash, a hang, unclear wording, or a policy the command refuses to read is also worth an
issue. For a vulnerability, follow [SECURITY.md](SECURITY.md) instead.

## Pull requests

Contributions are accepted under the [Apache License 2.0](LICENSE): by opening a pull request,
you agree that your contribution is licensed under it, as the licence's "Submission of
Contributions" clause says.

Before opening one, run:

```sh
make check
```

It must end with `all checks green`. CI runs the same checks on every pull request. The Go
version is the one in `go.mod`'s `toolchain` line; see [docs/OVERVIEW.md](docs/OVERVIEW.md)
for how the code is laid out.

The WebAssembly engine is checked by `web/engine/build.sh`, which needs TinyGo, Binaryen's
`wasm-opt`, `brotli` and Node, and which CI does not run; a change to `web/wasm` or
`web/engine` should pass it too.

What a change needs to be merged:

- **A change in behaviour comes with a test that fails without it.** Say in the pull request
  what the test checks and that you saw it fail before the change.
- **An answer that changes comes with its reason.** The corpus under `testdata/` pairs each
  document with a rationale file: what the document is, the expected answer, and the vendor
  documentation it rests on, quoted with its URL and the date it was read. The command's
  golden outputs under `cmd/cloudarq/testdata/` are rewritten with
  `go test ./cmd/cloudarq -update`; every golden file that changes needs its rationale to
  still be true, or to be corrected in the same pull request.
- **What the engine cannot read widens the answer.** A construct the parser does not model
  becomes Unknown on the claim it constrains, with a note that names it; it is never skipped,
  and it must not narrow who is admitted, which the property tests in `internal/parse/aws` and
  `internal/ring` check. A Deny that cannot be evaluated is not applied.
- **The pure packages stay pure.** `internal/eval`, `internal/join`, `internal/parse`,
  `internal/registry`, `internal/report`, `internal/ring` and `internal/trust` import no
  package that reaches the network, the filesystem or the environment, a subprocess, a system
  call or a source of randomness, except through `encoding/json`, `fmt`, `crypto/sha256` and
  `time`, which do IO only on a file or connection they are handed; `make purity` checks it,
  and `test/arch/purity_test.go` lists the packages.
- **Every statement stays covered** in `internal/eval`, `internal/trust`, `internal/parse` and
  `internal/ring`; `make cover` checks it.
- **Facts about an issuer are data.** Which claims name a tenant, the forms a subject takes and
  which condition keys AWS documents belong in the census module,
  [`github.com/CloudArq-net/issuers`](https://github.com/CloudArq-net/issuers), not in this
  repository's code.

Code is formatted with `gofmt`. Comments say why the code is the way it is. Commit messages say
what changed and why, in plain words.

## Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Reports go to
support@cloudarq.net.
