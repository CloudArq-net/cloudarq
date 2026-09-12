// Package eval is the lattice at the centre of CloudArq: a pure, deterministic
// algebra over sets of claim values, in which every finding is computed.
//
// A finding is one set difference, the values a condition admits minus the
// values the author intended, and StringSet is the type both sides are
// expressed in. Its constructors are Exact, Glob, Any, None and Unknown; Meet
// and Join are intersection and union. Nothing else lives here. What a cloud
// dialect means is the parser's problem, and what an API returned is the
// collector's, so this package can be tested to exhaustion in isolation.
//
// Two rules shape everything in it. Contains is exact for every set, so the
// lattice laws hold outright and are checked by property tests rather than
// argued. And a set answers IsEmpty or IsTop only when it can prove the
// answer; whenever a question is undecidable in this unit, such as whether
// two globs share a string, the answer is false. Reporting a dangerous policy
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
