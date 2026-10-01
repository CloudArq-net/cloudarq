// Package eval is the lattice at the centre of CloudArq: a pure, deterministic
// algebra over sets of claim values, in which every answer is computed.
//
// An answer is a set: the tokens a condition admits. Two types express it.
// StringSet is the set of values one claim may take, built from Exact,
// Glob, Any, None and Unknown, with Meet and Join as intersection and
// union; ShapeOf reads one back as the node it is, and LiteralPrefix says
// what every match of a pattern begins with, for a layer that reasons
// about how a constraint is written. AdmittedSet is the set of whole tokens
// a condition admits: a union of Terms, each Term a conjunction of
// per-claim StringSets, with Admits to test a token and Excludes to explain
// a rejection. Nothing else lives here. What a cloud dialect means is the
// parser's problem, and this package reads no document, so it can be
// tested to exhaustion in isolation.
//
// Two rules shape everything in it. Contains is exact for every set, so the
// lattice laws hold outright and are checked by property tests rather than
// argued. And a set answers IsEmpty or IsTop only when it can prove the
// answer; whenever a question is one this package does not decide, such as
// whether two globs share a string, the answer is false. Reporting a dangerous policy
// as admitting nothing is the worst output the program can produce, so
// undecided must never read as empty.
//
// Unknown is the top element with provenance: a constraint existed and could
// not be evaluated, so the claim is unconstrained as far as we can prove. It
// absorbs under Join, because an unevaluated branch could admit anything, and
// it is the identity under Meet, because an unevaluated AND-constraint can
// only ever narrow. Which constraint failed, and why, is recorded per result
// by the parser, not carried by the lattice.
//
// The package imports nothing that does IO, reads the clock or draws
// randomness, and a test in test/arch keeps it that way: the evaluator must
// stay fuzzable and byte-for-byte reproducible.
package eval
