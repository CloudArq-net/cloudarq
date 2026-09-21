// @cloudarq/explorer — the public surface.
//
// Anything not exported here is not a public surface and may change without a
// version bump. What is here is the component, the engine loader, the fragment
// grammar, the corpus documents the empty state offers, and the types of the
// answer the engine writes.
//
// The stylesheets are exported as package paths rather than imported by the
// component, so the host decides where a <link> goes and the page carries no
// inline style: `@cloudarq/explorer/tokens.css` and
// `@cloudarq/explorer/explorer.css`.
export { default as Explorer } from "./Explorer.svelte";

export { compileEngine, engineFor, loadEngine, type Engine, type EngineOptions } from "./engine.ts";
export {
	base64url,
	buildFragment,
	deflate,
	fragmentOf,
	inflate,
	parseFragment,
	readFragment,
	VIEWS,
	type Decoded,
	type Encoded,
	type View,
} from "./fragment.ts";
export { exampleNamed, examples, exampleText, openingDocument, type Example, type GlossRun } from "./examples.ts";
export {
	ANSWER_VERSION,
	type Answer,
	type Claim,
	type ClaimOutcome,
	type Constraint,
	type DocumentReport,
	type Excluded,
	type Explanation,
	type Grant,
	type Note,
	type Outcome,
	type Span,
	type Statement,
	type TokenReport,
	type Written,
} from "./answer.ts";
