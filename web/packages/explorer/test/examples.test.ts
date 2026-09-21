// The three documents the empty state offers are the corpus files, not a copy
// that drifted. web/build.sh asserts the same thing from outside the package,
// so that a release cannot pass on a package whose examples were edited; this
// asserts it where a developer runs the tests, which is where the drift would
// be introduced.
import { ok, strictEqual } from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { exampleNamed, examples, exampleText, openingDocument } from "../src/lib/examples.ts";

const repository = new URL("../../../../", import.meta.url);

test("every example is its corpus file byte for byte", () => {
	ok(examples.length > 0, "there are no examples, so nothing was compared");
	for (const example of examples) {
		const corpus = readFileSync(new URL(`testdata/grants/${example.name}/aws.json`, repository), "utf8");
		strictEqual(example.text, corpus, `the example ${example.name} differs from testdata/grants/${example.name}/aws.json`);
	}
});

test("the document the page opens with is one of them", () => {
	ok(exampleText(openingDocument).length > 0, `${openingDocument} is not among the examples`);
});

test("a document of the corpus is named, and a document of the reader's own is not", () => {
	strictEqual(exampleNamed(exampleText(openingDocument)), openingDocument);
	strictEqual(exampleNamed('{"Version":"2012-10-17","Statement":[]}'), "");
});

test("every gloss is runs of prose and code, and none of them is empty", () => {
	for (const example of examples) {
		ok(example.gloss.length > 0, `${example.name} has no gloss`);
		for (const run of example.gloss) ok(run.text.length > 0, `${example.name} has an empty gloss run`);
	}
});
