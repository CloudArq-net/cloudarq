// TinyGo's glue, as a value.
//
// wasm_exec.js is vendored verbatim from the toolchain — the file's first
// line records the version and the digest it was copied from — and the
// toolchain writes it for a classic <script> tag: it defines globalThis.Go
// unconditionally, and globalThis.fs and globalThis.process where the host
// has none. Nothing downstream of here reads a global, but a host page that
// embedded this package still got all three, and `process` defined in a
// browser is the branch condition a large amount of third-party code keys
// on.
//
// So the glue is loaded at a moment this module chooses rather than at
// import time, and the three names it writes are taken back by name. Not by
// difference: the load below is a network fetch on a hosted page — the glue
// is a chunk of its own — and a host is free to write to globalThis while it
// is in flight. Svelte does, and the write is load-bearing: window.__svelte
// is created lazily on the first $props.id() call and carries the counter
// that keeps two explorers' element ids apart, so a loader that deleted
// every name that appeared during its own load would delete the mechanism
// this package's ids depend on, and the second mount would start its ids
// again from the beginning.
//
// Reading the vendored source says taking the three back is safe: `fs` and
// `process` are compatibility shims the glue never reads back, and its one
// writer of output calls console.log directly (wasm_exec.js, fd_write). That
// the three are all of them is not left to the reading — web/package-check.mjs
// greps the vendored file for what it assigns to globalThis and fails when
// the set is not the one below. What is checked rather than read is narrower
// and worth more: the engine's own tests run admits, explain, a trap and a
// replacement past a memory bound with all three names gone.
//
// eval is not the alternative: the page is served under a policy with no
// 'unsafe-eval', so a wrapper that ran the glue's source in a scope of its
// own would be a wrapper that only works off the hosted origin.

/** The subset of TinyGo's Go class this package uses: an import object to
 *  instantiate against, and run() to initialise the instance. */
export interface GoRuntime {
	importObject: WebAssembly.Imports;
	run(instance: WebAssembly.Instance): Promise<void>;
}

interface GoConstructor {
	new (): GoRuntime;
}

/** The names TinyGo's glue writes onto globalThis: `Go` unconditionally,
 *  and `fs` and `process` where the host has none. */
export const GLUE_GLOBALS = ["Go", "fs", "process"] as const;

let loading: Promise<GoConstructor> | null = null;

/** goRuntime loads TinyGo's glue once and hands back its Go class. Every
 *  caller gets the same class, and globalThis is as it was before the first
 *  call. */
export function goRuntime(): Promise<GoConstructor> {
	loading ??= load();
	return loading;
}

async function load(): Promise<GoConstructor> {
	const global = globalThis as unknown as Record<string, unknown>;
	// A host with a Go, an fs or a process of its own gets it back exactly as
	// it was: the glue assigns `Go` without asking, where it guards the other
	// two behind a test.
	const before = GLUE_GLOBALS.map((name) => [name, Object.getOwnPropertyDescriptor(global, name)] as const);

	await import("./wasm_exec.js");

	const installed = global.Go as GoConstructor | undefined;
	if (!installed) throw new Error("wasm_exec.js did not define Go; the engine's glue is not the file this package ships");
	for (const [name, had] of before) {
		delete global[name];
		if (had) Object.defineProperty(global, name, had);
	}
	return installed;
}
