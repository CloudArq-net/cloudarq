# CloudArq

**Turns a cloud trust policy into the list of who it actually lets in.**

A trust policy is a rule about who may enter your cloud account. It is written in a small,
unforgiving language, and nobody reads it accurately — not the person who wrote it, and not the
tools that check it. That has two failure modes and they share one cause:

- **Too tight** and your deploy fails, with an error message that does not say why.
- **Too loose** and somebody who is not you can get in, and nothing tells you at all.

Both are legibility problems. CloudArq computes the **set of principals a condition admits**, and
then tells you what is on the other side of each one.

## Status

Pre-release. The evaluator is being built first; nothing here is usable yet.

## Design in one line

Every finding is one computation: the set of principals a condition **admits**, minus the set you
**intended**. A set difference, not a rule match.

This is the load-bearing decision. A rule encodes a *format*; a set encodes *admission*. Formats
change — GitHub changed its subject grammar in July 2026, AWS added five condition keys in
February — and rule-based tools need a patch each time. A lattice does not.

## Layout

| Path | Contract |
|---|---|
| `internal/eval` | **Pure.** The lattice. No IO, no clock, no randomness. 100% branch coverage, enforced. |
| `internal/parse/{aws,azure,gcp}` | **Pure.** Dialect text → AST → `AdmittedSet`. |
| `internal/evidence` | The provenance record. `Status` carries `denied` as a value. |
| `internal/collect` | **IO only.** Calls cloud APIs, emits `Evidence`. Never evaluates. |
| `internal/resolve` | **IO only.** Counterparty state. Allow-listed hosts only. |
| `internal/registry` | Embedded issuer data. Data, never a live fetch. |
| `test/arch` | Enforces the boundaries above as tests rather than conventions. |

The `internal/eval` ⇄ `internal/collect` boundary is the one that matters, and it is enforced by
`make purity`, which walks the transitive import graph and fails on `net`, `os`, `math/rand` or
any cloud SDK.

## Development

```bash
make check     # build, vet, test, purity, determinism, coverage, css
make purity    # layer boundaries
make cover     # internal/eval must be 100%
```

`make check` is what CI runs. There is no separate lint step to forget.

## Reading order

1. `docs/ENGINEERING.md` — the build rules. Every rule names the specific cost of breaking it.
2. `docs/ARCHITECTURE.md` — the layers and why each is shaped that way.

## Licence

Apache-2.0. The patent grant is deliberate: it is what corporate legal departments look for, and
it is what Prowler and Cartography use.
