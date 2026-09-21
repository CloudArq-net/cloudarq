// The address is the analysis.
//
//   #v1.<dialect>.<policy>.<token>.<view>
//
// policy and token are the pasted bytes, raw-deflated and base64url-encoded
// without padding; either may be empty. view is admits or token; admits is
// the default and is omitted, as is a trailing empty field. Every state has
// an address: #v1.aws is the empty one, and no fragment at all is the
// document the page opens with, whose own address it writes as it loads. A
// statement selection and a line mark are not in the link: they are how a
// reader looks at the analysis, not the analysis.
//
// The grammar is a published surface: links to it are in pull requests and
// in issues, and a link written by the page a year ago must still open the
// analysis it named. Changing any of it is a breaking change of this
// package, and a fragment this codec cannot read is refused by name rather
// than loaded as something else.

/** The two views the answer pane has. */
export const VIEWS = ["admits", "token"] as const;

export type View = (typeof VIEWS)[number];

/** A fragment's fields as the address spells them: the two documents still
 *  deflated and encoded. */
export interface Encoded {
	dialect: string;
	policy: string;
	token: string;
	view?: View;
}

/** A fragment's fields as the page holds them: the two documents as text. */
export interface Decoded {
	dialect: string;
	policy: string;
	token: string;
	view: View;
}

const isView = (v: string): v is View => (VIEWS as readonly string[]).includes(v);

/** parseFragment reads an address's fields. A fragment of another version
 *  reads as the empty state rather than as a guess at what its fields meant. */
export function parseFragment(hash: string): Decoded {
	const parts = hash.replace(/^#/, "").split(".");
	if (parts[0] !== "v1") return { dialect: "aws", policy: "", token: "", view: "admits" };
	return {
		dialect: parts[1] || "aws",
		policy: parts[2] || "",
		token: parts[3] || "",
		view: parts[4] !== undefined && isView(parts[4]) ? parts[4] : "admits",
	};
}

/** buildFragment spells an address from the encoded fields. The default view
 *  and every trailing empty field are dropped, so the empty state is `#v1.aws`
 *  and not `#v1.aws...`. */
export function buildFragment(encoded: Encoded): string {
	return "#" + ["v1", encoded.dialect, encoded.policy, encoded.token, encoded.view === "admits" ? "" : (encoded.view ?? "")].join(".").replace(/\.+$/, "");
}

/** base64url, without padding: the alphabet a URL fragment can carry
 *  unescaped. */
export const base64url = {
	encode(bytes: Uint8Array): string {
		let binary = "";
		for (const b of bytes) binary += String.fromCharCode(b);
		return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
	},
	decode(text: string): Uint8Array<ArrayBuffer> {
		const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
		const bytes = new Uint8Array(new ArrayBuffer(binary.length));
		for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
		return bytes;
	},
};

/** deflate compresses a document into the field an address carries. Empty
 *  text encodes as the empty field, not as the deflation of nothing: the
 *  address of the empty state is the shortest thing that can name it. */
export async function deflate(text: string): Promise<string> {
	if (!text) return "";
	const stream = new Blob([text]).stream().pipeThrough(new CompressionStream("deflate-raw"));
	return base64url.encode(new Uint8Array(await new Response(stream).arrayBuffer()));
}

/** inflate reads a document back out of an address's field. It throws on a
 *  field that is not the deflated text this codec writes, which is what a
 *  link cut short when it was copied looks like; the caller says so rather
 *  than showing an answer under an address it did not come from. */
export async function inflate(encoded: string): Promise<string> {
	if (!encoded) return "";
	const stream = new Blob([base64url.decode(encoded)]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
	return new Response(stream).text();
}

/** fragmentOf spells the whole address for a state. */
export async function fragmentOf(state: Decoded): Promise<string> {
	const [policy, token] = await Promise.all([deflate(state.policy), deflate(state.token)]);
	return buildFragment({ dialect: state.dialect, policy, token, view: state.view });
}

/** readFragment reads a whole address back into a state. It throws with the
 *  reason a reader is owed: a fragment of another version names its version,
 *  and one that will not inflate says what a truncated link looks like. */
export async function readFragment(hash: string): Promise<Decoded> {
	if (hash && !hash.startsWith("#v1.") && hash !== "#v1") {
		throw new Error(`it begins with ${hash.slice(1).split(".")[0]}, and this page reads v1`);
	}
	const parsed = parseFragment(hash);
	const [policy, token] = await Promise.all([inflate(parsed.policy), inflate(parsed.token)]);
	return { dialect: parsed.dialect, policy, token, view: parsed.view };
}
