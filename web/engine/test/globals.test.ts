// What the loader leaves on globalThis, measured across the load itself.
//
// This file imports nothing from the loader at the top. The glue TinyGo
// ships writes its names as it loads, so a snapshot taken after an import is
// a snapshot taken after the writes, and the names are outside the window it
// measures. A test that took its snapshot that way read zero added names
// while `Go` and `fs` sat on globalThis the whole time.
//
// node runs each test file in a process of its own, so the snapshot below is
// of a globalThis nothing in the loader has touched yet. node has a
// `process` of its own, so the glue leaves it alone here; in a browser it
// writes one, and go.ts takes it back by the same list.
import { deepStrictEqual, strictEqual } from "node:assert/strict";
import { test } from "node:test";

const own = () => new Set(Object.getOwnPropertyNames(globalThis));

test("importing the engine adds no name to globalThis", async () => {
	const before = own();
	const { loadEngine } = await import("../engine.ts");
	strictEqual(typeof loadEngine, "function");
	deepStrictEqual([...own()].filter((name) => !before.has(name)), [], "the import wrote names onto globalThis");
});

test("loading TinyGo's glue adds no name to globalThis", async () => {
	// The glue is what writes them, and it is loaded the moment an engine is
	// made. No WebAssembly is needed to prove what the load leaves behind,
	// which is why this is read here rather than beside the engine's own
	// tests: those need a build of the module and this needs nothing.
	const { goRuntime } = await import("../go.ts");
	const before = own();
	const Go = await goRuntime();
	strictEqual(typeof Go, "function", "the glue did not hand back a Go class");
	strictEqual(typeof new Go().importObject, "object", "the class the glue handed back does not instantiate");
	deepStrictEqual([...own()].filter((name) => !before.has(name)), [], "loading the glue wrote names onto globalThis");
});

test("the names the glue writes are not left behind", async () => {
	const { goRuntime } = await import("../go.ts");
	await goRuntime();
	// `Go` and `fs` are TinyGo's; `process` is one the glue installs where
	// the host has none. node has its own, which the glue leaves alone and
	// the loader must leave alone too.
	for (const name of ["Go", "fs", "admits", "explain"]) {
		strictEqual(Object.prototype.hasOwnProperty.call(globalThis, name), false, `the loader left ${name} on globalThis`);
	}
	strictEqual(globalThis.process?.version, process.version, "the loader replaced node's own process");
});
