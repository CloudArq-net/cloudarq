// The window while TinyGo's glue is loading belongs to the host.
//
// The glue is fetched as its own chunk on a hosted page, so the load spans a
// network round trip, and a host may write to globalThis inside it. Svelte
// does exactly that: window.__svelte is created lazily on the first
// $props.id() call and carries the uid counter that keeps two explorers'
// element ids apart. A loader that took back every name that appeared while
// it was loading would delete that counter and the next mount would start
// its ids again from the beginning — the cross-talk the id prefix exists to
// remove, reintroduced by the code that removes it.
//
// This file is its own test file rather than a case in globals.test.ts
// because node runs each file in a process of its own and goRuntime() loads
// once per process: a case that ran after another had already awaited it
// would have no window to write into.
import { deepStrictEqual, strictEqual } from "node:assert/strict";
import { test } from "node:test";

import { goRuntime } from "../src/lib/go.ts";

test("a name the host writes while the glue is loading is still there afterwards", async () => {
	const global = globalThis as unknown as Record<string, unknown>;
	const loading = goRuntime();
	// what Svelte's runtime keeps here, spelt the way it spells it
	global.__svelte = { uid: 7 };
	global.somethingTheHostOwns = "the host's";
	await loading;

	deepStrictEqual(global.__svelte, { uid: 7 }, "the loader deleted the host's element-id counter");
	strictEqual(global.somethingTheHostOwns, "the host's", "the loader deleted a name the host wrote while it was loading");

	// and the three the glue does write are still taken back
	for (const name of ["Go", "fs"]) {
		strictEqual(Object.prototype.hasOwnProperty.call(global, name), false, `the package left ${name} on globalThis`);
	}
	strictEqual(globalThis.process?.version, process.version, "the package replaced node's own process");

	delete global.__svelte;
	delete global.somethingTheHostOwns;
});
