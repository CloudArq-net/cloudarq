// The corpus documents the empty state offers, byte for byte the files under
// testdata/grants. They are here as text rather than as a fetch because the
// component must answer with no network of its own, and as a module rather
// than as an inline <script type="application/json"> because the page carries
// no inline anything; web/build.sh refuses to build when one of them differs
// from its corpus file.
//
// The gloss beside each name is the page's own words for what the document
// shows, and it is the one sentence here the engine did not write.

/** A run of a gloss: prose, or a value of the document set in code. */
export interface GlossRun {
	text: string;
	code?: boolean;
}

/** One document of the conformance corpus, as the empty state offers it. */
export interface Example {
	/** The corpus directory the document is testdata/grants/<name>/aws.json. */
	name: string;
	/** The document, byte for byte. */
	text: string;
	/** What the document shows, in the page's words. */
	gloss: GlossRun[];
}

const document03 = "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"GitHubWholeOrganisation\",\n      \"Effect\": \"Allow\",\n      \"Principal\": {\n        \"Federated\": \"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com\"\n      },\n      \"Action\": \"sts:AssumeRoleWithWebIdentity\",\n      \"Condition\": {\n        \"StringEquals\": {\n          \"token.actions.githubusercontent.com:aud\": \"sts.amazonaws.com\",\n          \"token.actions.githubusercontent.com:repository_owner_id\": \"123456\"\n        },\n        \"StringLike\": {\n          \"token.actions.githubusercontent.com:sub\": \"repo:acme/*\"\n        }\n      }\n    }\n  ]\n}\n";

const document06 = "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"GitHubUnconstrained\",\n      \"Effect\": \"Allow\",\n      \"Principal\": {\n        \"Federated\": \"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com\"\n      },\n      \"Action\": \"sts:AssumeRoleWithWebIdentity\",\n      \"Condition\": {\n        \"StringEquals\": {\n          \"token.actions.githubusercontent.com:aud\": \"sts.amazonaws.com\"\n        }\n      }\n    }\n  ]\n}\n";

const document07 = "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"GitHubForAllValues\",\n      \"Effect\": \"Allow\",\n      \"Principal\": {\n        \"Federated\": \"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com\"\n      },\n      \"Action\": \"sts:AssumeRoleWithWebIdentity\",\n      \"Condition\": {\n        \"StringEquals\": {\n          \"token.actions.githubusercontent.com:aud\": \"sts.amazonaws.com\",\n          \"token.actions.githubusercontent.com:repository_id\": \"456789\"\n        },\n        \"ForAllValues:StringLike\": {\n          \"token.actions.githubusercontent.com:sub\": \"repo:acme/infra:*\"\n        }\n      }\n    }\n  ]\n}\n";

/** The three documents the empty state offers, in the order it lists them. */
export const examples: Example[] = [
	{ name: "03-whole-organisation", text: document03, gloss: [{ text: "repo:acme/*", code: true }, { text: " with the owner id pinned" }] },
	{ name: "06-unconstrained", text: document06, gloss: [{ text: "the audience, and nothing else" }] },
	{ name: "07-expressible-by-one-provider", text: document07, gloss: [{ text: "ForAllValues:StringLike", code: true }, { text: " on " }, { text: "sub", code: true }] },
];

// The page opens answering. The document it opens with is a conformance
// case whose answer is the argument the page exists to make: a condition that
// reads as a constraint and is not one.
/** The document the page opens with when the address carries no fragment. */
export const openingDocument = "07-expressible-by-one-provider";

/** exampleNamed is the corpus name of a document, or the empty string: a
 *  document of the corpus is named wherever it is shown, so that a reader
 *  knows the answer on screen is not about anything of theirs. */
export function exampleNamed(text: string): string {
	return examples.find((e) => e.text === text)?.name ?? "";
}

/** exampleText is one corpus document by name. */
export function exampleText(name: string): string {
	return examples.find((e) => e.name === name)?.text ?? "";
}
