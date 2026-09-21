// The exports map against the README.
//
// A subpath that is not in the map cannot be reached by any standard
// resolution, whatever the tarball holds: node answers
// ERR_PACKAGE_PATH_NOT_EXPORTED and every bundler that reads the map answers
// the same. The README is the package's instructions, so every file it tells
// a consumer to reference is read out of it here and looked up in the map.
// web/consumer-check.mjs does the other half against a packed tarball, with
// node's own resolver rather than this one.
import { deepStrictEqual, ok } from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const at = (path: string) => new URL(path, import.meta.url);
const manifest = JSON.parse(readFileSync(at("../package.json"), "utf8")) as {
	name: string;
	exports: Record<string, string | Record<string, string>>;
};
const readme = readFileSync(at("../README.md"), "utf8");

// What a target resolves to, for the conditional entries as much as the
// plain ones: every condition of an entry is a file the entry can answer
// with.
const targets = (entry: string | Record<string, string>): string[] => (typeof entry === "string" ? [entry] : Object.values(entry));

test("every subpath the README names is in the exports map", () => {
	const named = [...new Set([...readme.matchAll(new RegExp(`${manifest.name}/([A-Za-z0-9_.\\-/]+)`, "g"))].map((m) => `./${m[1]}`))];
	ok(named.length > 0, "the README names no subpath of the package, so nothing was checked");
	const missing = named.filter((subpath) => !(subpath in manifest.exports));
	deepStrictEqual(missing, [], `the README names ${named.length} subpaths: ${named.join(", ")}`);
});

test("every shipped file the README names is reachable through the exports map", () => {
	// The README names a file inside the package — `dist/cloudarq.wasm` — for
	// a consumer to copy onto their own origin. A file named that way and not
	// exported is a file the instructions cannot be followed for.
	const inPackage = [...new Set([...readme.matchAll(/`(dist\/[A-Za-z0-9_.\-/]+)`/g)].map((m) => `./${m[1]}`))];
	ok(inPackage.length > 0, "the README names no file inside the package, so nothing was checked");
	const reachable = new Set(Object.values(manifest.exports).flatMap(targets));
	const unreachable = inPackage.filter((path) => !reachable.has(path));
	deepStrictEqual(unreachable, [], `the README names ${inPackage.length} shipped files: ${inPackage.join(", ")}`);
});
