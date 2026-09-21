// What the package leaves on globalThis, measured across the load itself.
//
// This file imports nothing from the package at the top. The glue TinyGo
// ships writes its names as it loads, so a snapshot taken after an import is
// a snapshot taken after the writes, and the names are outside the window it
// measures. The engine's own tests took theirs that way and read zero added
// names while `Go` and `fs` sat on globalThis the whole time.
//
// node runs each test file in a process of its own, so the snapshot below is
// of a globalThis nothing in this package has touched yet. What the page
// installs in a browser — where `process` is a name a large amount of
// third-party code branches on — is read in Chrome by web/consumer-check.mjs.
import { deepStrictEqual, strictEqual } from "node:assert/strict";
import { test } from "node:test";

const own = () => new Set(Object.getOwnPropertyNames(globalThis));

test("importing the engine adds no name to globalThis", async () => {
	const before = own();
	const { loadEngine } = await import("../src/lib/engine.ts");
	strictEqual(typeof loadEngine, "function");
	deepStrictEqual([...own()].filter((name) => !before.has(name)), [], "the import wrote names onto globalThis");
});

test("loading TinyGo's glue adds no name to globalThis", async () => {
	// The glue is what writes them, and it is loaded the moment an engine is
	// made. No WebAssembly is needed to prove what the load leaves behind,
	// which is why this is read here rather than beside the engine's own
	// tests: those need a build of the module and this needs nothing.
	const { goRuntime } = await import("../src/lib/go.ts");
	const before = own();
	const Go = await goRuntime();
	strictEqual(typeof Go, "function", "the glue did not hand back a Go class");
	strictEqual(typeof new Go().importObject, "object", "the class the glue handed back does not instantiate");
	deepStrictEqual([...own()].filter((name) => !before.has(name)), [], "loading the glue wrote names onto globalThis");
});

test("the names the glue writes are not left behind", async () => {
	const { goRuntime } = await import("../src/lib/go.ts");
	await goRuntime();
	// `Go` and `fs` are TinyGo's; `process` is one the glue installs where
	// the host has none. node has its own, which the glue leaves alone and
	// this package must leave alone too.
	for (const name of ["Go", "fs", "admits", "explain"]) {
		strictEqual(Object.prototype.hasOwnProperty.call(globalThis, name), false, `the package left ${name} on globalThis`);
	}
	strictEqual(globalThis.process?.version, process.version, "the package replaced node's own process");
});
