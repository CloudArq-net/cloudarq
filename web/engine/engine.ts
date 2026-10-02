// The engine: bytes in through the module's inbox, the answer out from where
// the module says it is.
//
// loadEngine returns an object and writes nothing to globalThis. Installing
// `admits` and `explain` as globals would answer correctly — the module is
// built -scheduler=none and a call completes before another can begin, so two
// holders sharing one inbox never interleave — but it would make the engine
// reachable from anywhere and let a second holder's load silently rebind the
// first holder's functions. An object handed to the caller is the same engine
// with the ambient reach removed.
//
// One instance per compiled module, shared by every holder: `engineFor` hands
// out one promise per module. Two instances would be two heaps (diff.mjs holds
// each to 36 MB on a 50-statement policy and 576 MB on the largest document
// the engine reads) for no correctness gain, because the inbox is never
// shared across an await. A holder therefore never owns the instance's
// lifecycle, and one holder going away never tears the engine down under
// another.
import { goRuntime } from "./go.ts";

/** What the engine answers with. Each call returns the JSON
 *  `internal/report` writes; a trap throws and the next call meets a live
 *  engine. */
export interface Engine {
	/** admits reads a trust policy and answers who it lets in. */
	admits(policy: string): string;
	/** explain reads a policy and a token and answers, per grant, whether the
	 *  token is admitted and why. */
	explain(policy: string, token: string): string;
	/** findings reads a bundle cloudarq-collect wrote, as the file's bytes so
	 *  that the hash it records is the file's, and the owners declared as
	 *  yours, one a line; it answers every role in it as
	 *  cloudarq.findings/v1. */
	findings(bundle: Uint8Array, owners: string): string;
	/** memoryBytes is the live instance's linear memory, for the gates that
	 *  watch where the heap settles. */
	memoryBytes(): number;
	/** peakMemoryBytes is the highest level any instance of this engine
	 *  reached. */
	peakMemoryBytes(): number;
	/** replacements counts the instances replaced past the memory bound or
	 *  after a trap. The call after a replacement runs on a fresh instance,
	 *  whose heap grows again from its initial size. */
	replacements(): number;
}

export interface EngineOptions {
	/** The linear memory past which the instance is replaced. Linear memory
	 *  never shrinks and TinyGo's collector doubles it rather than compact, so
	 *  a tab without a bound has no ceiling. The default is 256 MB; the bound
	 *  is a parameter so that the replacement can be proven on a small one. */
	memoryBound?: number;
}

interface EngineExports extends WebAssembly.Exports {
	memory: WebAssembly.Memory;
	reserve(n: number): number;
	answerAt(): number;
	admits(policyLength: number): number;
	explain(policyLength: number, tokenLength: number): number;
	findings(bundleLength: number, ownersLength: number): number;
}

/** loadEngine instantiates one engine over a compiled module. Prefer
 *  `engineFor`, which hands every holder the same instance. */
export async function loadEngine(module: WebAssembly.Module, { memoryBound = 1 << 28 }: EngineOptions = {}): Promise<Engine> {
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	// The glue is loaded here rather than imported: go.ts takes back the names
	// the vendored file writes onto globalThis, which it can only do around a
	// load of its own. It is loaded once per page or process; a replacement
	// after a trap has the class already.
	const Go = await goRuntime();
	// A library module initialises and returns: wasm_exec's run() calls the
	// module's _initialize before its first await, so an instance is ready as
	// soon as run() has been called, and the promise only carries an exit
	// that never comes. The instance is kept warm across calls: a fresh one
	// grows its heap again from its initial size, which in node took the
	// first call on the largest document the engine reads to 156 ms against
	// 81 ms on a warm instance (medians, measured 2026-09-27).
	function fresh(): WebAssembly.Instance {
		const go = new Go();
		const instance = new WebAssembly.Instance(module, go.importObject);
		void go.run(instance);
		return instance;
	}
	let instance = fresh();
	let replaced = 0;
	let peak = 0;
	// A pointer the module returns is a wasm i32, which reads as negative once
	// memory has grown past 2 GB; memory.buffer is read after every call into
	// the module, because growth replaces the buffer.
	const call = (name: "admits" | "explain" | "findings", parts: Uint8Array[]): string => {
		const exports = instance.exports as EngineExports;
		const { memory, reserve, answerAt } = exports;
		let text: string;
		try {
			const at = reserve(parts.reduce((n, p) => n + p.length, 0)) >>> 0;
			let offset = 0;
			for (const p of parts) {
				new Uint8Array(memory.buffer, at + offset, p.length).set(p);
				offset += p.length;
			}
			const length =
				name === "admits" ? exports.admits(parts[0].length) : exports[name](parts[0].length, parts[1].length);
			text = decoder.decode(new Uint8Array(memory.buffer, answerAt() >>> 0, length));
		} catch (err) {
			// a trap leaves the instance dead, every later call throwing too;
			// the caller is told once and the next call meets a live engine
			instance = fresh();
			replaced++;
			throw err;
		}
		peak = Math.max(peak, memory.buffer.byteLength);
		if (memory.buffer.byteLength > memoryBound) {
			instance = fresh();
			replaced++;
		}
		return text;
	};
	// Every method reads `instance` at call time rather than closing over the
	// exports it had at load: a holder that captured them would keep calling a
	// dead instance after a trap, and would read the replaced instance's memory
	// after a bound replacement.
	return {
		admits: (policy) => call("admits", [encoder.encode(policy)]),
		explain: (policy, token) => call("explain", [encoder.encode(policy), encoder.encode(token)]),
		findings: (bundle, owners) => call("findings", [bundle, encoder.encode(owners)]),
		memoryBytes: () => (instance.exports as EngineExports).memory.buffer.byteLength,
		peakMemoryBytes: () => peak,
		replacements: () => replaced,
	};
}

// One engine per compiled module, for every holder of it. The map is keyed
// on the module rather than on a URL, so a caller that compiled the bytes
// itself — a test in node, a build script — gets the same sharing as a page
// that fetched them.
const engines = new WeakMap<WebAssembly.Module, Promise<Engine>>();

/** engineFor hands every holder of one compiled module the same engine. A
 *  second holder never starts a second instance, and no holder owns the
 *  instance's lifecycle: there is nothing to tear down when one unmounts.
 *  Options are read only when the engine is first made. */
export function engineFor(module: WebAssembly.Module, options?: EngineOptions): Promise<Engine> {
	const existing = engines.get(module);
	if (existing) return existing;
	const made = loadEngine(module, options);
	engines.set(module, made);
	return made;
}

/** compileEngine fetches and compiles the engine from a URL. The loader
 *  never names a URL of its own: the caller says where the bytes are, so a
 *  page's `connect-src` names only the origins its host chose. */
export async function compileEngine(url: string | URL): Promise<WebAssembly.Module> {
	return WebAssembly.compileStreaming(fetch(url));
}
