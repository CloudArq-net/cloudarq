// The vendored glue: that it is TinyGo's file, and that go.ts takes back
// every name it writes.
//
// go.ts takes back the names TinyGo's glue writes onto globalThis by name
// rather than by difference, because names that appear while the glue loads
// may be the host's. That is only sound while GLUE_GLOBALS is the whole list,
// so the vendored file is read for what it assigns to globalThis and the two
// sets are compared: a re-vendored glue that installed a fourth name would
// otherwise leave it on every page that loads the engine, and nothing would
// say so.
import { createHash } from "node:crypto";
import { deepStrictEqual, ok, strictEqual } from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { GLUE_GLOBALS } from "../go.ts";

const glue = readFileSync(new URL("../wasm_exec.js", import.meta.url), "utf8");

test("wasm_exec.js is TinyGo's file, unchanged below the line that names it", () => {
	const newline = glue.indexOf("\n");
	const header = glue.slice(0, newline);
	const recorded = header.match(/^\/\/ wasm_exec\.js from TinyGo [0-9.]+ \(targets\/wasm_exec\.js, sha256 ([0-9a-f]{64})\)/)?.[1];
	ok(recorded, `the first line does not record TinyGo's version and the file's sha256: ${header}`);
	strictEqual(createHash("sha256").update(glue.slice(newline + 1)).digest("hex"), recorded, "the vendored file is not the one its first line names");
});

test("go.ts takes back every name the vendored glue writes", () => {
	const writes = [...new Set([...glue.matchAll(/^\s*globalThis\.([A-Za-z_$][A-Za-z0-9_$]*)\s*=/gm)].map((m) => m[1]))].sort();
	ok(writes.length > 0, "no assignment to globalThis was found in wasm_exec.js, so nothing was compared");
	deepStrictEqual(writes, [...GLUE_GLOBALS].sort(), "the names the glue writes are not the names go.ts takes back");
});
