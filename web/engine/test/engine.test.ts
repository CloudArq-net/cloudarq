// The loader's contract.
//
// A loader that wrote `admits` and `explain` onto globalThis would answer
// correctly — the module is built -scheduler=none and no call spans an
// await, so two holders over one inbox never interleave — but the engine
// would be reachable from anywhere and a second holder's load would rebind
// the first holder's functions. These tests are the contract that rules it
// out, and the first of them fails on a loader that writes both names. The
// other half of that contract — that nothing the loader imports leaves a
// name behind either — is in globals.test.ts, because it can only be
// measured by a file that has imported nothing yet.
//
// The engine is the built wasm. There is nothing to mock: a mocked engine
// would prove that the mock answers, which is not the thing worth knowing.
import { deepStrictEqual, notDeepStrictEqual, ok, strictEqual, notStrictEqual } from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { compileEngine, engineFor, loadEngine } from "../engine.ts";

// paths are resolved against the repository root rather than against the
// working directory, so the tests run the same from any directory
const repository = new URL("../../../", import.meta.url);
if (!process.env.CLOUDARQ_WASM) {
	// web/engine/build.sh builds the module and passes it in. There is no
	// default path to fall back on: a stale build found on disk would be
	// tested in place of the one just built.
	throw new Error("CLOUDARQ_WASM is not set: these tests need the engine built as WebAssembly, which web/engine/build.sh builds and passes in");
}
const bytes = readFileSync(new URL(process.env.CLOUDARQ_WASM, repository));
const module = await WebAssembly.compile(bytes);
// documents of the corpus, read as the command reads them
const corpusDocument = (name: string) => readFileSync(new URL(`testdata/grants/${name}/aws.json`, repository), "utf8");
const policy = corpusDocument("03-whole-organisation");
const token = JSON.stringify({ iss: "https://token.actions.githubusercontent.com", aud: "sts.amazonaws.com", sub: "repo:acme/infra:ref:refs/heads/main", repository_owner_id: "123456" });

test("loadEngine returns the engine rather than naming it on globalThis", async () => {
	const engine = await loadEngine(module);
	strictEqual(typeof engine.admits, "function");
	strictEqual(typeof engine.explain, "function");
	strictEqual((globalThis as Record<string, unknown>).admits, undefined, "loadEngine wrote admits onto globalThis");
	strictEqual((globalThis as Record<string, unknown>).explain, undefined, "loadEngine wrote explain onto globalThis");
	// What the import itself leaves behind is measured in globals.test.ts,
	// which imports nothing at the top: the glue writes its names as it
	// loads, so a count taken in this file is taken after the writes and
	// cannot see them.
});

test("the engine answers, and the answer is version 1 of the schema", async () => {
	const engine = await loadEngine(module);
	const answer = JSON.parse(engine.admits(policy));
	strictEqual(answer.v, 1);
	strictEqual(answer.grants.length, 1);
	ok(answer.grants[0].sentence.length > 0);
	const explained = JSON.parse(engine.explain(policy, token));
	strictEqual(explained.v, 1);
	strictEqual(explained.grants.length, 1);
});

test("remark re-marks a role the findings kept as the findings answer it with the owners declared now", async () => {
	const engine = await loadEngine(module);
	const bundle = new TextEncoder().encode(JSON.stringify({
		format: "cloudarq.collect/v1", provider: "aws", account: "123456789012", partition: "aws",
		pages: [{ Roles: [{ RoleName: "deploy", Arn: "arn:aws:iam::123456789012:role/deploy", AssumeRolePolicyDocument: policy }] }],
		refused: [], limits: [],
	}));
	const kept = JSON.parse(engine.findings(bundle, ""));
	const now = JSON.parse(engine.findings(bundle, "github:acme"));
	// the owner moves the role, or re-marking it would prove nothing
	notDeepStrictEqual(now.roles[0].answer, kept.roles[0].answer);
	const remarked = engine.remark(JSON.stringify(kept.roles[0].answer), "github:acme", kept.engine);
	deepStrictEqual(JSON.parse(remarked), now.roles[0].answer);
	const declined = JSON.parse(engine.remark(JSON.stringify(kept.roles[0].answer), "github:acme", `${kept.engine}-another-build`));
	strictEqual(declined.v, 1);
	strictEqual(declined.declined, "engine");
	ok(declined.sentence.length > 0);
});

test("fixed makes the whole fixed policy from the bundle, the one a proven fix names by its digest, and no answer carries it", async () => {
	const engine = await loadEngine(module);
	const partner = JSON.stringify({
		Version: "2012-10-17",
		Statement: [
			{ Effect: "Allow", Principal: { Service: "ec2.amazonaws.com" }, Action: "sts:AssumeRole" },
			{ Sid: "Partner", Effect: "Allow", Principal: { AWS: ["arn:aws:iam::111122223333:root", "444455556666"] }, Action: "sts:AssumeRole" },
		],
	});
	const arn = "arn:aws:iam::123456789012:role/partner";
	const bundle = new TextEncoder().encode(JSON.stringify({
		format: "cloudarq.collect/v1", provider: "aws", account: "123456789012", partition: "aws",
		pages: [{ Roles: [{ RoleName: "partner", Arn: arn, AssumeRolePolicyDocument: partner }] }],
		refused: [], limits: [],
	}));
	const findings = engine.findings(bundle, "aws:444455556666");
	const fix = JSON.parse(findings).roles[0].answer.grants
		.flatMap((g: { populations?: { way?: { fix?: { status: string; edit?: { sha256: string; leaf: { start: number; end: number } } } } }[] }) => g.populations ?? [])
		.map((p: { way?: { fix?: { status: string; edit?: { sha256: string; leaf: { start: number; end: number } } } } }) => p.way?.fix)
		.find((f: { status: string } | undefined) => f?.status === "proven");
	ok(fix?.edit, "the partner's account has no proven fix");
	const fixed = JSON.parse(engine.fixed(bundle, "aws:444455556666", arn, fix.edit.leaf.start, fix.edit.leaf.end));
	const want = partner.replace(`"arn:aws:iam::111122223333:root",`, "");
	strictEqual(fixed.policy, want);
	strictEqual(fixed.sha256, fix.edit.sha256);
	strictEqual(fixed.error, undefined);
	ok(!findings.includes(JSON.stringify(want).slice(1, -1)), "the findings carry the fixed policy");
	const refused = JSON.parse(engine.fixed(bundle, "aws:444455556666", arn, fix.edit.leaf.start + 1, fix.edit.leaf.end));
	strictEqual(refused.policy, undefined);
	ok(refused.error.length > 0);
});

test("fixed makes the policy that lets no one in where removing the principal would leave no statement, and no answer carries it", async () => {
	const engine = await loadEngine(module);
	const alone = JSON.stringify({
		Version: "2012-10-17",
		Statement: [{ Sid: "Partner", Effect: "Allow", Principal: { AWS: "arn:aws:iam::111122223333:root" }, Action: "sts:AssumeRole" }],
	});
	const arn = "arn:aws:iam::123456789012:role/partner";
	const bundle = new TextEncoder().encode(JSON.stringify({
		format: "cloudarq.collect/v1", provider: "aws", account: "123456789012", partition: "aws",
		pages: [{ Roles: [{ RoleName: "partner", Arn: arn, AssumeRolePolicyDocument: alone }] }],
		refused: [], limits: [],
	}));
	const findings = engine.findings(bundle, "");
	const fix = JSON.parse(findings).roles[0].answer.grants[0].populations[0].way.fix;
	strictEqual(fix.status, "proven");
	strictEqual(fix.edit.removes, "policy");
	const fixed = JSON.parse(engine.fixed(bundle, "", arn, fix.edit.leaf.start, fix.edit.leaf.end));
	const want = '{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Sid": "DenyEveryone",\n      "Effect": "Deny",\n      "Principal": {"AWS": "*"},\n      "Action": "sts:AssumeRole"\n    }\n  ]\n}';
	strictEqual(fixed.policy, want);
	strictEqual(fixed.sha256, fix.edit.sha256);
	strictEqual(fixed.error, undefined);
	ok(!findings.includes("DenyEveryone"), "the findings carry the policy that replaces it");
	// the replacement, answered on its own, lets no one in
	const again = JSON.parse(engine.admits(fixed.policy));
	ok(again.grants.length > 0);
	for (const g of again.grants) {
		strictEqual(g.effect, "Deny");
		deepStrictEqual(g.placement, ["refused"]);
	}
});

test("two loaders over one module are two holders and neither rebinds the other", async () => {
	const a = await loadEngine(module);
	const b = await loadEngine(module);
	notStrictEqual(a.admits, b.admits);
	const sixOfA = a.admits(corpusDocument("06-unconstrained"));
	const threeOfB = b.admits(policy);
	strictEqual(a.admits(corpusDocument("06-unconstrained")), sixOfA);
	strictEqual(b.admits(policy), threeOfB);
	notStrictEqual(sixOfA, threeOfB);
});

test("engineFor hands every holder of one module the same engine", async () => {
	const first = engineFor(module);
	const second = engineFor(module);
	strictEqual(first, second, "two holders started two instances over one module");
	strictEqual(await first, await second);
	const other = await WebAssembly.compile(bytes);
	notStrictEqual(engineFor(other), first, "a second module was answered by the first module's engine");
});

test("a holder's engine is live after the instance is replaced past its memory bound", async () => {
	// The bound is small enough that the document below crosses it, so the
	// replacement is deterministic rather than a matter of where a run's
	// doublings land.
	const engine = await loadEngine(module, { memoryBound: 1 << 20 });
	const before = engine.admits(policy);
	let calls = 0;
	while (engine.replacements() === 0 && calls < 50) {
		engine.admits(policy);
		calls++;
	}
	ok(engine.replacements() > 0, `the engine was never replaced over ${calls} calls on a 1 MB bound`);
	strictEqual(engine.admits(policy), before, "the call after a replacement did not answer as the call before it did");
	ok(engine.memoryBytes() > 0, "memoryBytes read a dead instance");
	ok(engine.peakMemoryBytes() >= engine.memoryBytes());
});

test("a holder's engine is live after a trap", async () => {
	const trapping = process.env.CLOUDARQ_TRAPPING_WASM;
	if (!trapping) {
		// The engine's own build is not known to trap on any document, so the
		// path is proven on a build linked with the toolchain's 64 KB stack,
		// which web/engine/build.sh writes and passes in. Without it there is nothing to
		// trap, and a test that quietly passed on that would be a vacuous one.
		throw new Error("CLOUDARQ_TRAPPING_WASM is not set: the trap-recovery path cannot be exercised, and a test that cannot run is not a test that passed");
	}
	const engine = await loadEngine(await WebAssembly.compile(readFileSync(new URL(trapping, repository))));
	const deep = "{" + '"a":{'.repeat(125) + "}".repeat(126);
	let trapped: unknown = null;
	try {
		engine.admits(deep);
	} catch (err) {
		trapped = err;
	}
	ok(trapped !== null, "the 64 KB-stack build did not trap on a document nested 125 levels deep");
	strictEqual(engine.replacements(), 1);
	const answer = JSON.parse(engine.admits(policy));
	strictEqual(answer.grants.length, 1, "the call after a trap did not meet a live engine");
});

test("compileEngine names no URL of its own", () => {
	// The loader never hardcodes where the bytes are: the caller passes a URL
	// or a module, so a page's connect-src names only the origins its host
	// chose. A signature that took no argument would be a URL.
	strictEqual(compileEngine.length, 1);
});
