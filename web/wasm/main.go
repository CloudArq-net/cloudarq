//go:build js && wasm

// The engine as a WebAssembly module: a reactor module whose exports carry
// bytes in and the answer out, and nothing else. The loader in web/engine
// (engine.ts, loadEngine) wraps them as admits(policyText),
// explain(policyText, tokenText), findings(bundleBytes, ownersText),
// remark(answerText, ownersText, engineText) and fixed(bundleBytes,
// ownersText, roleArn, start, end) on the object it returns, each
// returning the JSON internal/report renders; web/wasm/native renders the
// same bytes for the differential.
//
// The module is built with no scheduler and as a library (-scheduler=none
// -buildmode=c-shared): the exports are synchronous and never block,
// so the asyncify instrumentation that syscall/js callbacks need would only
// double the code size, and a library keeps its exports callable for the
// life of the instance instead of ending with main.
package main

import "github.com/CloudArq-net/cloudarq/internal/report"

// inbox holds the caller's bytes, one input after another: the policy and
// the token; the bundle and the owners; or an answer, the owners and the
// engine that wrote the answer. outbox holds the last answer until the next
// call writes the next one over it: the caller has read an answer before it
// calls again, so the buffer is kept rather than a new one made for every
// answer. Both are reachable from here so that the collector keeps them
// while the caller reads them; the collector does not move objects, so the
// addresses handed out stay valid.
var (
	inbox  []byte
	outbox []byte
)

// version is the engine's version the findings name, and the one an answer
// given to remark must have been written by, set by the linker
// (web/engine/build.sh).
var version = "0.0.0-dev"

// reserve makes room for n bytes of input and returns where to write them.
//
//go:wasmexport reserve
func reserve(n int32) *byte {
	inbox = make([]byte, n)
	if n == 0 {
		return nil
	}
	return &inbox[0]
}

// admits answers for the policy in the first policyLen bytes of the inbox
// and returns the answer's length.
//
//go:wasmexport admits
func admits(policyLen int32) int32 {
	outbox = report.AppendAdmits(outbox[:0], inbox[:policyLen])
	return int32(len(outbox))
}

// explain answers for the policy in the first policyLen bytes of the inbox
// and the token in the tokenLen bytes after it.
//
//go:wasmexport explain
func explain(policyLen, tokenLen int32) int32 {
	outbox = report.AppendExplain(outbox[:0], inbox[:policyLen], inbox[policyLen:policyLen+tokenLen])
	return int32(len(outbox))
}

// findings answers every role of the bundle in the first bundleLen bytes of
// the inbox, with the owners declared in the ownersLen bytes after it, one a
// line, and returns the findings' length.
//
//go:wasmexport findings
func findings(bundleLen, ownersLen int32) int32 {
	outbox = report.AppendFindings(outbox[:0], inbox[:bundleLen], inbox[bundleLen:bundleLen+ownersLen], engine())
	return int32(len(outbox))
}

// remark re-marks the answer in the first answerLen bytes of the inbox with
// the owners declared in the ownersLen bytes after it, one a line; the
// engineLen bytes after those name the engine the scan's findings say wrote
// the answer. It returns the length of what report.Remark renders: the
// answer for those owners, or why it is declined. One answer a call, never
// a whole findings file: the heap doubles on large inputs and never
// shrinks.
//
//go:wasmexport remark
func remark(answerLen, ownersLen, engineLen int32) int32 {
	owners := inbox[answerLen : answerLen+ownersLen]
	wrote := inbox[answerLen+ownersLen : answerLen+ownersLen+engineLen]
	outbox = report.AppendRemark(outbox[:0], inbox[:answerLen], owners, string(wrote), engine())
	return int32(len(outbox))
}

// fixed answers with the trust policy of the role whose ARN is in the
// arnLen bytes after the bundle in the first bundleLen bytes of the inbox
// and the owners declared in the ownersLen bytes after it, one a line, with
// the principal written at bytes [start, end) of that policy removed, as
// the role's answer proves the edit, or why it is not given. The policy is
// the reader's own and is made here, from the bundle they hold; no answer
// carries it.
//
//go:wasmexport fixed
func fixed(bundleLen, ownersLen, arnLen, start, end int32) int32 {
	owners := inbox[bundleLen : bundleLen+ownersLen]
	arn := inbox[bundleLen+ownersLen : bundleLen+ownersLen+arnLen]
	outbox = report.AppendFixed(outbox[:0], inbox[:bundleLen], owners, string(arn), int(start), int(end))
	return int32(len(outbox))
}

// engine is this build's name, as the findings it writes record it.
func engine() string { return "cloudarq " + version }

// answerAt is where the last answer's bytes start.
//
//go:wasmexport answerAt
func answerAt() *byte {
	if len(outbox) == 0 {
		return nil
	}
	return &outbox[0]
}

// main is not run: a library module initialises and waits to be called.
func main() {}
