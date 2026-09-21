// The fragment grammar, against addresses the shipped page actually wrote.
//
// Links to this page are in pull requests and in issues, and a link the page
// wrote a year ago must still open the analysis it named. So the fixtures
// below are not round trips of this codec against itself — those prove only
// that it agrees with itself. They were read out of Chrome from the page as
// it shipped, on 2026-09-21, by driving web/dist and reading location.hash:
// the address the opening document writes for itself, the address a pasted
// document gets, and the address of the empty state.
//
// Node and Chrome spell deflate-raw identically (checked on node v22.21.0
// against the capture, below), which is why this can be a node test rather
// than a browser one.
import { deepStrictEqual, ok, strictEqual } from "node:assert/strict";
import { test } from "node:test";

import { buildFragment, deflate, fragmentOf, inflate, parseFragment, readFragment, VIEWS } from "../src/lib/fragment.ts";
import { exampleText, openingDocument } from "../src/lib/examples.ts";

// read out of Chrome from the shipped page, 2026-09-21
const shipped = {
	openingDocument:
		"#v1.aws.nVFLTwIxEL7vr2h6NIDs-kB72xhQEw9GEjgYY2Z3B5jQbbGdSpDw300XAutNvcwcvvkeM7NNhJATdJ6skUrIrJ9m3bTfTQeyE6ExA2ONhqUSr4kQQmybGiGqIuOe-CEUI-tyrSegA_qG2YwMZzMsI1XmWtv1CXh2ZEpagZbqKCiEHGGFDhgbYXBGwdorglqpNLu4vLoe3Nz200xZqsruytlPqtCds12i6UHJZI3vzYkXoQgeXWkNo-FeaWt5sNgdA-TNeLTx7FXufajxxWqcEi-mWDxWaJh4c0p8Z01FB04r8ZgdmfnwI4D2PxAh5C-CKQjVIUQPaviyBta-Sdz5q5LDlfXE1m3e94_Z30sedXad1qFb71L7HZ5oif_ZwIciukV7BWWN52RmDtRZyzhp91jfkl3yDQ",
	typedEmptyStatement: {
		text: '{"Version":"2012-10-17","Statement":[]}',
		hash: "#v1.aws.q1YKSy0qzszPU7JSMjIwNNI1NNA1NFfSUQouSSxJzU3NK1Gyio6tBQA",
	},
	empty: "#v1.aws",
};

test("the address the opening document writes for itself is the one the shipped page wrote", async () => {
	const hash = await fragmentOf({ dialect: "aws", policy: exampleText(openingDocument), token: "", view: "admits" });
	strictEqual(hash, shipped.openingDocument);
});

test("a pasted document gets the address the shipped page gave it", async () => {
	const hash = await fragmentOf({ dialect: "aws", policy: shipped.typedEmptyStatement.text, token: "", view: "admits" });
	strictEqual(hash, shipped.typedEmptyStatement.hash);
});

test("the empty state's address is #v1.aws, and it is not the absent fragment", async () => {
	strictEqual(await fragmentOf({ dialect: "aws", policy: "", token: "", view: "admits" }), shipped.empty);
	strictEqual(buildFragment({ dialect: "aws", policy: "", token: "", view: "admits" }), "#v1.aws");
});

test("an address the shipped page wrote reads back as the document it named", async () => {
	const state = await readFragment(shipped.openingDocument);
	strictEqual(state.policy, exampleText(openingDocument));
	strictEqual(state.token, "");
	strictEqual(state.view, "admits");
	strictEqual(state.dialect, "aws");
});

test("the token field and the view round-trip", async () => {
	const token = '{"sub":"repo:acme/infra:ref:refs/heads/main"}';
	const policy = exampleText("03-whole-organisation");
	const hash = await fragmentOf({ dialect: "aws", policy, token, view: "token" });
	ok(hash.endsWith(".token"), `the view is the last field: ${hash}`);
	deepStrictEqual(await readFragment(hash), { dialect: "aws", policy, token, view: "token" });
});

test("the default view is omitted and a trailing empty field is dropped", () => {
	strictEqual(buildFragment({ dialect: "aws", policy: "AAA", token: "", view: "admits" }), "#v1.aws.AAA");
	strictEqual(buildFragment({ dialect: "aws", policy: "AAA", token: "BBB", view: "admits" }), "#v1.aws.AAA.BBB");
	strictEqual(buildFragment({ dialect: "aws", policy: "AAA", token: "", view: "token" }), "#v1.aws.AAA..token");
});

test("a fragment of another version reads as the empty state rather than as a guess", () => {
	deepStrictEqual(parseFragment("#v2.aws.AAA"), { dialect: "aws", policy: "", token: "", view: "admits" });
});

test("a whole address of another version is refused by name", async () => {
	await readFragment("#v2.aws.abc").then(
		() => {
			throw new Error("a v2 address was read as if it were a v1 one");
		},
		(err: Error) => ok(err.message.includes("this page reads v1"), err.message),
	);
});

test("a link cut short when it was copied is refused, not decoded into something else", async () => {
	const whole = await fragmentOf({ dialect: "aws", policy: exampleText("03-whole-organisation"), token: "", view: "admits" });
	await readFragment(whole.slice(0, 200)).then(
		() => {
			throw new Error("a truncated address inflated to something");
		},
		(err: unknown) => ok(err instanceof Error),
	);
});

test("a view the grammar does not name falls back to admits", () => {
	strictEqual(parseFragment("#v1.aws.AAA.BBB.witness").view, "admits");
	deepStrictEqual([...VIEWS], ["admits", "token"]);
});

test("the empty document encodes as the empty field, not as the deflation of nothing", async () => {
	strictEqual(await deflate(""), "");
	strictEqual(await inflate(""), "");
});

test("a document with characters beyond ASCII survives the address", async () => {
	const policy = '{"Sid":"Café ☃ 😀","Statement":[]}';
	const hash = await fragmentOf({ dialect: "aws", policy, token: "", view: "admits" });
	strictEqual((await readFragment(hash)).policy, policy);
});
