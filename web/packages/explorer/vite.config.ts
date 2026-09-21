// The standalone page's build.
//
// Vite compiles the page; the `.svelte` transform below is this package's
// own, because `@sveltejs/vite-plugin-svelte` is not in the approved
// dependency set and adding one is a decision, not a convenience. What the
// plugin does is the whole of what this build needs: hand a component's
// source to the compiler `svelte` already ships, and put the component's own
// stylesheet — if it ever grows one — into the bundle as a file rather than
// inline, because the page is served under a policy with no 'unsafe-inline'.
import { compile } from "svelte/compiler";
import { defineConfig, type Plugin } from "vite";

import config from "./svelte.config.js";

// The suffix ends in .css on purpose: Vite decides what a module is from its
// id, and an id that did not end in .css was handed to the JavaScript parser,
// which reported a stylesheet as a syntax error.
const CSS_SUFFIX = "?cloudarq-svelte.css";

/** svelte compiles a component for a build. It is exported because the
 *  consumer gate builds a page against the packed tarball with the same
 *  transform this page is built with: two transforms would be two answers to
 *  what a component compiles to. */
export function svelte(): Plugin {
	// a component's emitted stylesheet, by the component's own id
	const stylesheets = new Map<string, string>();
	return {
		name: "cloudarq:svelte",
		// Ahead of Vite's own resolver. The stylesheet is asked for by the
		// component's own path with a suffix on it, and vite:resolve answers
		// that specifier first — it strips the query, finds the .svelte file on
		// disk and hands it back as a module — so a resolveId in the normal
		// bucket never sees it, `load` never runs, and the component's source
		// reaches the bundler as JavaScript. A component with a <style> failed
		// to build that way, which is how this was found.
		enforce: "pre",
		resolveId(id) {
			return id.endsWith(CSS_SUFFIX) ? "\0" + id : null;
		},
		load(id) {
			if (!id.startsWith("\0") || !id.endsWith(CSS_SUFFIX)) return null;
			return stylesheets.get(id.slice(1, -CSS_SUFFIX.length)) ?? "";
		},
		transform(source, id) {
			if (!id.endsWith(".svelte")) return null;
			const compiled = compile(source, { ...config.compilerOptions, filename: id, generate: "client", css: "external", dev: false });
			for (const warning of compiled.warnings) {
				// A warning that nobody reads is a warning that does not exist, and
				// the component templates are where a whitespace or an a11y mistake
				// would hide.
				this.warn(`${warning.code}: ${warning.message} (${id})`);
			}
			let code = compiled.js.code;
			if (compiled.css?.code) {
				stylesheets.set(id, compiled.css.code);
				code += `\nimport ${JSON.stringify(id + CSS_SUFFIX)};\n`;
			}
			return { code, map: compiled.js.map };
		},
	};
}

export default defineConfig({
	root: "src/page",
	base: "./",
	plugins: [svelte()],
	resolve: { dedupe: ["svelte"], conditions: ["svelte", "browser"] },
	build: {
		// web/dist, relative to `root`, which is where Vite resolves build paths
		// from. It is the directory web/build.sh has always written the page
		// into and the one `npx wrangler pages dev web/dist` serves: this page
		// is the standalone page, not a second one beside it, and two pages that
		// look alike are two things to keep in agreement.
		outDir: "../../../../dist",
		emptyOutDir: true,
		manifest: true,
		// Nothing becomes a data: URI. The page is served under a policy that
		// allows img-src data: and nothing else, and an asset that inlined itself
		// would be an asset the policy has never been asked about.
		assetsInlineLimit: 0,
		cssCodeSplit: false,
		// The stylesheet ships as it is written. Minifying it would put values
		// in the build that nobody chose — Vite's CSS minifier adds custom
		// properties of its own — and the gate that says the design system is
		// one file reads the built CSS, not the source.
		cssMinify: false,
		sourcemap: false,
		target: "es2022",
	},
});
