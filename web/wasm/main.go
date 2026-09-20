//go:build js && wasm

// The explorer's WebAssembly engine: a reactor module whose exports carry
// bytes in and the answer out, and nothing else. The page's loader
// (web/app.js, loadEngine) wraps them as admits(policyText) and
// explain(policyText, tokenText) on globalThis, each returning the JSON the
// answer package renders; the native helper renders the same bytes for the
// differential.
//
// The module is built with no scheduler and as a library (-scheduler=none
// -buildmode=c-shared): the two functions are synchronous and never block,
// so the asyncify instrumentation that syscall/js callbacks need would only
// double the code size, and a library keeps its exports callable for the
// life of the page instead of ending with main.
package main

import "github.com/CloudArq-net/cloudarq/web/wasm/answer"

// inbox holds the caller's bytes: the policy, then the token when there is
// one. outbox holds the last answer until the next call replaces it. Both
// are reachable from here so that the collector keeps them while the
// caller reads them; the collector does not move objects, so the addresses
// handed out stay valid.
var (
	inbox  []byte
	outbox []byte
)

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
	outbox = answer.Admits(inbox[:policyLen])
	return int32(len(outbox))
}

// explain answers for the policy in the first policyLen bytes of the inbox
// and the token in the tokenLen bytes after it.
//
//go:wasmexport explain
func explain(policyLen, tokenLen int32) int32 {
	outbox = answer.Explain(inbox[:policyLen], inbox[policyLen:policyLen+tokenLen])
	return int32(len(outbox))
}

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
