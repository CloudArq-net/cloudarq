// The explorer package's own rules, read off the source and off what it
// builds. Everything here is a count or a byte comparison; nothing needs a
// browser, so this is the half of the gate that can run in CI.
//
//   node web/package-check.mjs
//
// Eight rules, each printing what it examined:
//
//   carried      the package's LICENSE is the repository's, by digest. A
//                package that publishes a different licence from the
//                repository it comes out of is one nobody can rely on.
//   licences     every package npm put on disk, read at the version
//                installed: none under GPL, AGPL or SSPL, and the ones
//                outside the permissive list named rather than left to a
//                reader of the lockfile.
//   glue         src/lib/go.ts takes back exactly the names the vendored
//                wasm_exec.js writes to globalThis, which is what makes
//                taking them back by name — rather than by the difference of
//                a snapshot, which belongs to the host — sound.
//   examples     the three corpus documents the empty state offers are the
//                corpus files, byte for byte.
//   greps        the idioms product/LAUNCH-STANDARD.md §3 and
//                docs/ENGINEERING.md §9 forbid, over the package's own source
//                and — for the decoration set, which is the set the Makefile's
//                css target greps every file under web/ for — over the built
//                page as well, so the two gates read the same bytes and
//                cannot disagree about them. node_modules stays out of both:
//                a dependency's own stylesheet is not this product's taste.
//   G-tokens     in the built CSS of the page, the only custom-property
//                declarations are the ones in the package's tokens file; in
//                the component source, none at all. This is the design
//                system being one file, made into a count instead of a hope.
//   G-routes     every file the build manifest names is in the build, every
//                reference in a built page resolves to a file in it, and no
//                built file is unreferenced. A link walk that examined zero
//                links is not a link walk.
//   budget       the page's own bytes — its runtime, its code, its stylesheet,
//                its markup and its typefaces — gzipped, itemised, against
//                the 100 KB row in product/directions/BRIEF.md item 7. Every
//                item is measured off the build; none of them is a number
//                this file states. The engine's own 400 KB budget is separate
//                and web/build.sh measures it.
//
// Exits non-zero on the first rule that is broken, and on a rule that
// examined nothing: a gate over an empty set is not a gate.
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { extname, join, relative, resolve } from "node:path";

const root = resolve(new URL("..", import.meta.url).pathname);
const pkg = join(root, "web/packages/explorer");
// The page the package builds is the standalone page, at web/dist: the
// directory web/build.sh writes and `npx wrangler pages dev web/dist` serves.
const site = join(root, "web/dist");
const lib = join(pkg, "src/lib");

let broken = 0;
const rule = (ok, name, detail) => {
	console.log(`  ${ok ? "clean" : "FAIL "} ${name}: ${detail}`);
	if (!ok) broken++;
};

const digest = (path) => execFileSync("shasum", ["-a", "256", path], { encoding: "utf8" }).split(" ")[0];
const gzipped = (path) => execFileSync("bash", ["-c", `gzip -9 -c ${JSON.stringify(path)} | wc -c`], { encoding: "utf8" }).trim();

// Every file under a directory. What is skipped is an argument and not a
// constant, because the two walks here are asking different questions and an
// exclusion that suits one is a hole in the other. Reading the source, npm's
// trees and the build's outputs are not the subject: npm places any version
// it cannot hoist under web/packages/*/node_modules, and a Vite or Svelte
// tree carries every idiom the greps forbid. Reading the build, nothing is
// skipped at all: every byte under the directory is a byte the host serves,
// and a file the walk stepped over is a file the rules below cannot see while
// the Pages emulator answers 200 for it.
const NOT_OURS = new Set(["node_modules"]);
const WRITTEN_BY_A_BUILD = new Set(["dist", "site", ".svelte-kit", ".vite"]);
const SOURCE_ONLY = new Set([...NOT_OURS, ...WRITTEN_BY_A_BUILD]);
function filesUnder(dir, extensions, skip = SOURCE_ONLY) {
	const out = [];
	const walk = (at) => {
		for (const entry of readdirSync(at, { withFileTypes: true })) {
			if (skip.has(entry.name)) continue;
			const path = join(at, entry.name);
			if (entry.isDirectory()) walk(path);
			else if (!extensions || extensions.has(extname(entry.name))) out.push(path);
		}
	};
	walk(dir);
	return out.sort();
}
// Nothing under the directory the build writes is skipped, and a font is a
// file the page's byte budget is spent on, so the extensions the build is
// read for are wider than the source's.
const NOTHING = new Set();
const TYPEFACES = new Set([".woff2", ".woff", ".ttf", ".otf"]);

console.log("── carried unchanged ──");
{
	// This rule compared the stylesheet, the tokens file and the vendored glue
	// against the copies the shipped page wore while both existed. The shipped
	// page is gone — the standalone page replaced it, and web/index.html,
	// web/app.js, web/app.css, web/tokens.css and web/wasm_exec.js with it — so
	// those three rows would now compare a file with nothing. What carries the
	// move instead is measured elsewhere and is stronger: the rendering
	// differential holds every sentence to web/text-fixture.json, captured off
	// the shipped page before a line of the component was written, and
	// web/page-check.mjs measures every contrast pair in Chrome against the
	// ratio written beside its token. The one row with a counterpart still in
	// the tree is the licence, and a package that ships a different one from the
	// repository it is published out of is a package nobody can rely on.
	const carried = [["LICENSE", "LICENSE"]];
	const differ = carried.filter(([mine, theirs]) => digest(join(pkg, mine)) !== digest(join(root, theirs)));
	rule(differ.length === 0 && carried.length > 0, "the carried files are byte-identical to their sources",
		differ.length ? differ.map(([mine, theirs]) => `${mine} differs from ${theirs}`).join("; ") : `${carried.length} file compared by sha256`);
}

console.log();
console.log("── the licences in the installed tree ──");
{
	// Every package npm put on disk, read at the version that is installed.
	// docs/ENGINEERING.md §7 forbids GPL and AGPL outright and allows MPL only
	// where nothing under it ships, so the census names the MPL packages rather
	// than leaving them to a reader of the lockfile. Two are here today —
	// lightningcss and its platform binary, transitives of vite — and what
	// keeps them out of the build is measured a few rules below: the build sets
	// cssMinify false and the built stylesheet is the tokens file verbatim, so
	// the minifier never writes a byte the page serves.
	const permissive = /^(MIT|ISC|0BSD|BSD-2-Clause|BSD-3-Clause|Apache-2.0|Unlicense|CC0-1.0|BlueOak-1.0.0|Python-2.0|MIT-0)$/;
	const refused = /GPL|SSPL|CDDL|EPL|Commons Clause/i;
	const installed = [];
	const walkModules = (at) => {
		let entries;
		try {
			entries = readdirSync(at, { withFileTypes: true });
		} catch {
			return;
		}
		for (const entry of entries) {
			if (!entry.isDirectory() && !entry.isSymbolicLink()) continue;
			const path = join(at, entry.name);
			if (entry.name.startsWith("@")) {
				walkModules(path);
				continue;
			}
			try {
				const manifest = JSON.parse(readFileSync(join(path, "package.json"), "utf8"));
				const license = typeof manifest.license === "string" ? manifest.license : (manifest.license?.type ?? manifest.licenses?.[0]?.type ?? "");
				installed.push([manifest.name ?? relative(root, path), manifest.version ?? "", license]);
			} catch {}
			walkModules(join(path, "node_modules"));
		}
	};
	walkModules(join(root, "node_modules"));
	const named = installed.filter(([, , license]) => license !== "");
	const forbidden = named.filter(([, , license]) => refused.test(license) && !/LGPL-3.0-or-later OR GPL/.test(license));
	const weak = named.filter(([, , license]) => !permissive.test(license) && !refused.test(license));
	console.log(`  ${named.length} packages installed with a licence field${weak.length ? `; not on the permissive list: ${weak.map(([name, version, license]) => `${name}@${version} ${license}`).join(", ")}` : ""}`);
	rule(installed.length > 0 && forbidden.length === 0, "no GPL, AGPL or SSPL package is installed",
		installed.length === 0 ? "no package.json was read under node_modules, so nothing was censused"
			: forbidden.length ? forbidden.map(([name, version, license]) => `${name}@${version} ${license}`).join(", ")
				: `${installed.length} packages walked, ${named.length} of them naming a licence`);
}

console.log();
console.log("── the glue's names ──");
{
	// src/lib/go.ts takes back the names TinyGo's glue writes by name rather
	// than by difference, because the difference belongs to the host. That is
	// only sound while the list is the whole list, so the vendored file is
	// grepped for what it assigns to globalThis and the two sets are compared.
	// A re-vendored glue that installed a fourth name would otherwise leak it
	// onto every page that embeds this package, and nothing would say so.
	const glue = readFileSync(join(lib, "wasm_exec.js"), "utf8");
	const writes = [...new Set([...glue.matchAll(/^\s*globalThis\.([A-Za-z_$][A-Za-z0-9_$]*)\s*=/gm)].map((m) => m[1]))].sort();
	const taken = [...new Set(JSON.parse(
		readFileSync(join(lib, "go.ts"), "utf8").match(/GLUE_GLOBALS = (\[[^\]]*\])/)?.[1].replace(/'/g, '"') ?? "[]",
	))].sort();
	rule(writes.length > 0 && taken.length > 0 && writes.join() === taken.join(), "go.ts takes back every name the vendored glue writes",
		writes.length === 0 ? "no assignment to globalThis was found in src/lib/wasm_exec.js, so nothing was compared"
			: taken.length === 0 ? "GLUE_GLOBALS was not read out of src/lib/go.ts, so nothing was compared"
				: writes.join() !== taken.join() ? `the glue writes ${writes.join(", ")}; go.ts takes back ${taken.join(", ")}`
					: `${writes.length} names written by src/lib/wasm_exec.js and taken back by src/lib/go.ts: ${writes.join(", ")}`);
}

console.log();
console.log("── examples ──");
{
	const source = readFileSync(join(lib, "examples.ts"), "utf8");
	const names = [...source.matchAll(/name: "([^"]+)", text: (document\d+)/g)].map((m) => [m[1], m[2]]);
	const texts = Object.fromEntries([...source.matchAll(/^const (document\d+) = ("(?:[^"\\]|\\.)*");$/gm)].map((m) => [m[1], JSON.parse(m[2])]));
	const wrong = names.filter(([name, id]) => texts[id] !== readFileSync(join(root, `testdata/grants/${name}/aws.json`), "utf8"));
	rule(names.length > 0 && wrong.length === 0, "every example is its corpus file byte for byte",
		names.length === 0 ? "no example was read out of src/lib/examples.ts, so nothing was compared"
			: wrong.length ? wrong.map(([name]) => `${name} differs from testdata/grants/${name}/aws.json`).join("; ")
				: `${names.length} embedded documents equal their corpus files`);
}

console.log();
console.log("── the page's own rules ──");
{
	// Declarations are read with comments stripped, because a comment declares
	// nothing: the tokens file states a contrast ratio beside every ink and
	// those numbers are prose, not values.
	const strip = (path, text) =>
		path.endsWith(".html") ? text.replace(/<!--[^]*?-->/g, "")
			: path.endsWith(".svelte") ? text.replace(/<!--[^]*?-->/g, "").replace(/\/\*[^]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "")
				: text.replace(/\/\*[^]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
	// The vendored glue is TinyGo's, copied verbatim, and it is not this
	// product's prose; it is compared by digest above instead.
	const sources = filesUnder(join(pkg, "src"), new Set([".svelte", ".ts", ".css", ".html"])).filter((p) => !p.endsWith("wasm_exec.js"));
	const built = filesUnder(site, new Set([".css", ".js", ".html", ...TYPEFACES]), NOTHING);
	const lines = (paths) => paths.flatMap((path) => strip(path, readFileSync(path, "utf8")).split("\n").map((text, i) => [`${relative(root, path)}:${i + 1}`, text]));
	// The tokens file is the one place a colour or a length literal may appear,
	// so it is not in the set the colour and length greps read; that it holds
	// them is the whole point of it.
	const styling = sources.filter((p) => !p.endsWith("tokens.css"));

	const grep = (name, paths, pattern, allowed = () => false) => {
		const all = lines(paths);
		const hits = all.filter(([, text]) => pattern.test(text)).filter(([at, text]) => !allowed(at, text));
		rule(hits.length === 0, name, `${all.length} declaration lines over ${paths.length} files${hits.length ? `\n         ${hits.map(([at, text]) => `${at}: ${text.trim()}`).join("\n         ")}` : ""}`);
	};

	// The words are spelt with a character class so that this file can carry
	// the rule without matching itself.
	// The one grep that reads the built page as well as the source. The
	// Makefile's css target greps every file under web/ for these idioms and
	// a build writes its output under web/, so a gate that skipped the build
	// would be calling clean exactly the bytes that make check fails on.
	grep("no decoration", [...sources, ...built.filter((p) => !TYPEFACES.has(extname(p)))], /gr[a]dient|blur-\[|backdrop-f[i]lter|cyb[e]r-|drop-sh[a]dow|box-sh[a]dow|border-radius: *([4-9]|[1-9][0-9])px/);
	grep("no colour outside the tokens", styling, /#[0-9a-fA-F]{3,8}\b|transparent|currentColor|rgb\(|hsl\(/);
	// The one length outside the tokens is the media-query breakpoint, which a
	// custom property cannot express.
	grep("no length outside the tokens", styling, /[0-9](px|rem|em|ch|lh)\b/, (at, text) => /@media/.test(text));
	grep("no motion outside the tokens", styling, /transition:|animation:|@keyframes|scroll-behavior|transition:|animate:/);
	grep("no literal duration outside the tokens", styling.filter((p) => p.endsWith(".css") || p.endsWith(".html")), /[0-9](\.[0-9]+)?m?s\b/);
	grep("no verdict in the page", sources, /severity|critical|posture|verdict|badge|hero|dashboard|!important|TODO|FIXME|XXX/i);
	grep("the page never says the forbidden noun", sources, /secur/i);
	// product/pass1/FOUNDATION-critique.md, amendment 9: a Svelte transition or
	// animate directive injects an inline <style>, and the page is served under
	// a policy with no 'unsafe-inline'. Motion is CSS under a named token.
	grep("no svelte transition or animate directive", sources.filter((p) => p.endsWith(".svelte")), /\b(transition|in|out|animate):[a-z]/);
	// The page carries no inline script and no inline style: what the built
	// HTML holds is <link> and <script src>, and nothing between the tags.
	const builtHtml = built.filter((p) => p.endsWith(".html"));
	const inline = builtHtml.flatMap((path) => {
		const html = readFileSync(path, "utf8");
		return [...html.matchAll(/<(script|style)\b([^>]*)>([^]*?)<\/\1>/g)]
			.filter((m) => m[1] === "style" || (!/\bsrc=/.test(m[2]) && m[3].trim().length > 0))
			.map((m) => `${relative(root, path)}: <${m[1]}${m[2]}>`);
	});
	rule(builtHtml.length > 0 && inline.length === 0, "the built page carries no inline script and no inline style",
		builtHtml.length === 0 ? `no HTML was found under ${relative(root, site)}, so nothing was read` : inline.length ? inline.join("; ") : `${builtHtml.length} built page(s) read`);

	console.log();
	console.log("── G-tokens ──");
	const declarationsIn = (text) => [...text.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;}]*)/g)].map((m) => [m[1], m[2].trim()]);
	const tokensSource = readFileSync(join(lib, "tokens.css"), "utf8");
	const tokens = [...new Set(declarationsIn(tokensSource).map(([name]) => name))];
	const builtCss = built.filter((p) => p.endsWith(".css"));
	// The built stylesheet is the source, unminified, so what the browser reads
	// is what the file says; a minifier that rewrote a value would be a value
	// nobody decided, and lightningcss adds custom properties of its own.
	const notCarried = builtCss.filter((p) => !readFileSync(p, "utf8").includes(tokensSource.trim().slice(0, 200)));
	rule(builtCss.length > 0 && notCarried.length === 0, "the built stylesheet carries the tokens file as written",
		builtCss.length === 0 ? `no CSS was found under ${relative(root, site)}, so nothing was checked`
			: notCarried.length ? notCarried.map((p) => relative(site, p)).join(", ") : `${builtCss.length} built stylesheet(s) open with tokens.css verbatim`);

	// A custom property declared outside the tokens file may only pass a token
	// through: main { --split: var(--split-default) } is the pane's state, not
	// a value somebody chose here, and `--accent: #f00` in a component is.
	const passesAToken = (value) => /^var\(--[a-z0-9-]+\)$/.test(value);
	const declaredElsewhere = [...builtCss, ...styling.filter((p) => p.endsWith(".css"))].flatMap((p) =>
		declarationsIn(readFileSync(p, "utf8")).filter(([name]) => !tokens.includes(name)).map(([name, value]) => [relative(root, p), name, value]),
	);
	const chosenElsewhere = declaredElsewhere.filter(([, , value]) => !passesAToken(value));
	rule(tokens.length > 0 && builtCss.length > 0 && chosenElsewhere.length === 0,
		"every custom property outside the tokens file only passes a token through",
		tokens.length === 0 ? "no token was read out of tokens.css, so nothing was checked"
			: builtCss.length === 0 ? `no CSS was found under ${relative(root, site)}, so nothing was checked`
				: chosenElsewhere.length ? chosenElsewhere.map(([at, name, value]) => `${at}: ${name}: ${value}`).join("; ")
					: `${tokens.length} tokens declared, ${declaredElsewhere.length} declaration(s) elsewhere and each of them a var() of a token`);

	// A style attribute or a Svelte style: directive never reaches a
	// stylesheet, so the built CSS cannot see it; the markup is read for both.
	const markup = styling.filter((p) => p.endsWith(".svelte") || p.endsWith(".html"));
	const inMarkup = lines(markup).filter(([, text]) => /--[a-z0-9-]+\s*:/.test(text) || /\sstyle=|\sstyle:[a-z-]/.test(text));
	rule(markup.length > 0 && inMarkup.length === 0, "no custom property and no style attribute in the component markup",
		markup.length === 0 ? "no markup was read, so nothing was checked"
			: inMarkup.length ? inMarkup.map(([at, text]) => `${at}: ${text.trim()}`).join("; ")
				: `${lines(markup).length} lines of markup read over ${markup.length} files`);

	// The census: every token declared is read by name somewhere, and every
	// name read is declared. The second half catches a token renamed in one
	// file and not the other, which no stylesheet reports.
	const declaredAnywhere = new Set([...sources, ...builtCss].flatMap((p) => declarationsIn(readFileSync(p, "utf8")).map(([name]) => name)));
	const read = [...new Set(
		[...sources, ...builtCss].flatMap((p) => [...readFileSync(p, "utf8").matchAll(/var\((--[a-z0-9-]+)|getPropertyValue\("(--[a-z0-9-]+)"\)/g)].map((m) => m[1] ?? m[2])),
	)];
	const unused = tokens.filter((t) => !read.includes(t));
	const undeclared = read.filter((t) => !declaredAnywhere.has(t));
	rule(unused.length === 0 && undeclared.length === 0, "every token is declared and consumed",
		`${tokens.length} declared in tokens.css, ${read.length} names read across the package${unused.length ? `; unused: ${unused.join(", ")}` : ""}${undeclared.length ? `; never declared: ${undeclared.join(", ")}` : ""}`);

	console.log();
	console.log("── G-routes ──");
	const manifest = JSON.parse(readFileSync(join(site, ".vite/manifest.json"), "utf8"));
	const named = new Set();
	for (const entry of Object.values(manifest)) {
		if (entry.file) named.add(entry.file);
		for (const css of entry.css ?? []) named.add(css);
		for (const asset of entry.assets ?? []) named.add(asset);
	}
	const inBuild = new Set(filesUnder(site, null, NOTHING).map((p) => relative(site, p)));
	const missing = [...named].filter((p) => !inBuild.has(p));
	rule(named.size > 0 && missing.length === 0, "every file the build manifest names is in the build",
		named.size === 0 ? "the manifest names no file, so nothing was checked" : missing.length ? missing.join(", ") : `${named.size} files named, all present among the ${inBuild.size} in the build`);

	// every reference out of every built page, resolved
	const references = builtHtml.flatMap((path) =>
		[...readFileSync(path, "utf8").matchAll(/\s(?:href|src)="([^"]+)"/g)].map((m) => [relative(root, path), m[1]]),
	);
	const unresolved = references.filter(([, href]) => {
		if (href.startsWith("#") || href.startsWith("data:")) return false;
		if (/^[a-z]+:/.test(href)) return true; // nothing external is linked from the built page
		return !inBuild.has(href.replace(/^\.?\//, ""));
	});
	rule(references.length > 0 && unresolved.length === 0, "every reference in a built page resolves to a file in the build",
		references.length === 0 ? "no reference was found in any built page, so nothing was walked" : unresolved.length ? unresolved.map(([at, href]) => `${at} -> ${href}`).join(", ") : `${references.length} references over ${builtHtml.length} page(s)`);

	// A built file nothing reaches is a file the deploy carries and the page
	// never asks for. Three are carried on purpose: the engine and the header
	// file are the host's rather than the bundler's, and Vite's own manifest
	// is what the routes rule above reads, so it ships with the build it
	// describes. Every other file under the directory has to be reachable,
	// including the ones under a dot directory — the walk that finds them
	// skips nothing, because the Pages emulator serves them either way.
	const hosts = new Set(["cloudarq.wasm", "_headers", ".vite/manifest.json"]);
	const reachable = new Set([...named, ...references.map(([, href]) => href.replace(/^\.?\//, "")), "index.html", ...hosts]);
	const stranded = [...inBuild].filter((p) => !reachable.has(p));
	rule(stranded.length === 0, "no file in the build is unreachable from it", stranded.length ? stranded.join(", ") : `${inBuild.size} files in the build, all reached`);

	console.log();
	console.log("── the page's byte budget ──");
	// product/directions/BRIEF.md item 7: 100 KB gzipped for the page's own
	// CSS, JS and fonts, the engine excluded. The typefaces are read off the
	// build like every other item rather than stated: this unit ships none,
	// and the row that would hold a font the day 2b adds one is the row that
	// has to find it, not a sentence saying there is nothing to find.
	const budget = 100000;
	const fonts = built.filter((p) => TYPEFACES.has(extname(p)));
	const items = [...builtHtml, ...builtCss, ...built.filter((p) => p.endsWith(".js")), ...fonts]
		.map((p) => [relative(site, p), Number(gzipped(p))])
		.sort((a, b) => b[1] - a[1]);
	const total = items.reduce((n, [, bytes]) => n + bytes, 0);
	console.log(`  ${items.map(([name, bytes]) => `${name} ${bytes}`).join(" · ")} · ${fonts.length} typeface${fonts.length === 1 ? "" : "s"} among them`);
	rule(items.length > 0 && total <= budget, "the page's own bytes are within the budget",
		items.length === 0 ? "nothing was measured" : `${total} bytes gzip -9 over ${items.length} files, against the ${budget} byte budget (${budget - total} bytes of headroom)`);
}

console.log();
if (broken) {
	console.error(`FAIL: ${broken} of the package rules are broken`);
	process.exit(1);
}
console.log("the package rules: all clean");
