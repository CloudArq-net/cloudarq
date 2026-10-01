// The window while TinyGo's glue is loading belongs to the host.
//
// When a bundler makes the glue a chunk of its own, the load spans a
// network round trip, and the host may write to globalThis inside it: a UI
// framework may create a global lazily and keep in it a counter its
// components depend on. A loader that took back every name that appeared
// while it was loading would delete that counter.
//
// This file is its own test file rather than a case in globals.test.ts
// because node runs each file in a process of its own and goRuntime() loads
// once per process: a case that ran after another had already awaited it
// would have no window to write into.
import { deepStrictEqual, strictEqual } from "node:assert/strict";
import { test } from "node:test";

import { goRuntime } from "../go.ts";

test("a name the host writes while the glue is loading is still there afterwards", async () => {
	const global = globalThis as unknown as Record<string, unknown>;
	const loading = goRuntime();
	// a counter a UI framework might keep here
	global.__framework = { uid: 7 };
	global.somethingTheHostOwns = "the host's";
	await loading;

	deepStrictEqual(global.__framework, { uid: 7 }, "the loader deleted the host's counter");
	strictEqual(global.somethingTheHostOwns, "the host's", "the loader deleted a name the host wrote while it was loading");

	// and the three the glue does write are still taken back
	for (const name of ["Go", "fs"]) {
		strictEqual(Object.prototype.hasOwnProperty.call(global, name), false, `the loader left ${name} on globalThis`);
	}
	strictEqual(globalThis.process?.version, process.version, "the loader replaced node's own process");

	delete global.__framework;
	delete global.somethingTheHostOwns;
});
