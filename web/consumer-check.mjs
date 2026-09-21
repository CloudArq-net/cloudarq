// What a host that installs @cloudarq/explorer gets.
//
//   node web/consumer-check.mjs <tarball> <axe.min.js>
//
// The package's own gate reads the source and the page this repository
// builds. This one starts from the tarball web/build.sh packs and names by
// digest, because that is what a consumer installs, and it asks the three
// questions that only a second mount can answer:
//
//   exports    every subpath the README tells a consumer to reference
//              resolves through node's own resolver, out of an install of
//              the tarball. A file inside the package with no entry in the
//              exports map cannot be reached by any standard resolution,
//              whatever the tarball holds.
//   two mounts the README's own snippet, used twice: no id is spelt twice,
//              no reference in one explorer resolves into the other, the
//              page has at most one main landmark, axe finds no violation,
//              and only the explorer the host gave the address to writes it.
//   unmount    an explorer removed from the page rewrites nothing
//              afterwards. Its two address writes are scheduled
//              differently — a keystroke's waits in a task, a link's is
//              already past its await — so the run leaves one of each
//              outstanding when the explorer goes, and reads the address a
//              second later.
//
// The page is built with the same Svelte transform web/packages/explorer
// builds its own page with, from web/packages/explorer/vite.config.ts: two
// transforms would be two answers to what a component compiles to.
//
// Exits non-zero on the first thing that reads wrong, and on a check that
// examined nothing.
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

import { findChrome, launch, serveDirectory, settleOn } from "./chrome.mjs";

const [tarball, axePath] = process.argv.slice(2);
if (!tarball || !axePath) {
  console.error("usage: node web/consumer-check.mjs <tarball> <axe.min.js>");
  process.exit(2);
}
const root = resolve(new URL("..", import.meta.url).pathname);
const pkg = join(root, "web/packages/explorer");

let axeSource;
try {
  axeSource = readFileSync(axePath, "utf8");
} catch (err) {
  console.error(`consumer check: not run, ${axePath} could not be read (${err.message}); the accessibility audit is a gate, not an option`);
  process.exit(1);
}
if (axeSource.length < 100000) {
  console.error(`consumer check: not run, ${axePath} is ${axeSource.length} bytes, which is not the axe-core bundle`);
  process.exit(1);
}
const chromePath = findChrome();
if (!chromePath) {
  console.error("consumer check: not run, no Chrome found; set CHROME to the browser's path");
  process.exit(1);
}

let checks = 0;
const failures = [];
function check(name, ok, detail) {
  checks++;
  console.log(`  ${ok ? "clean" : "FAIL "} ${name}: ${detail}`);
  if (!ok) failures.push(name);
}

// ---- the install ----

// npm's own extraction, into the layout a resolver expects. `npm install
// <tarball>` would reach the registry for the peer dependency; the bytes
// under test are the tarball's, and svelte is the one this repository
// already has installed, linked in as a consumer's node_modules would hold
// it.
const work = mkdtempSync(join(tmpdir(), "cloudarq-consumer-"));
const consumer = join(work, "consumer");
const modules = join(consumer, "node_modules");
mkdirSync(join(modules, "@cloudarq"), { recursive: true });
execFileSync("tar", ["-xzf", resolve(tarball), "-C", join(modules, "@cloudarq")]);
execFileSync("mv", [join(modules, "@cloudarq/package"), join(modules, "@cloudarq/explorer")]);
symlinkSync(join(root, "node_modules/svelte"), join(modules, "svelte"));
writeFileSync(join(consumer, "package.json"), JSON.stringify({ name: "a-host-page", private: true, type: "module" }, null, 2) + "\n");

console.log("── the exports map, through node's own resolver ──");
const readme = readFileSync(join(pkg, "README.md"), "utf8");
// what the README tells a consumer to write, read out of the README itself
const specifiers = [...new Set([...readme.matchAll(/@cloudarq\/explorer(\/[A-Za-z0-9_.\-/]+)?/g)].map((m) => `@cloudarq/explorer${m[1] ?? ""}`))].sort();
const require = createRequire(join(consumer, "index.js"));
const resolved = new Map();
const unresolved = [];
for (const specifier of specifiers) {
  try {
    resolved.set(specifier, require.resolve(specifier));
  } catch (err) {
    unresolved.push(`${specifier} -> ${err.code || err.message}`);
  }
}
check("every specifier the README names resolves out of the installed package", specifiers.length > 0 && unresolved.length === 0,
  specifiers.length === 0 ? "the README names no specifier, so nothing was resolved" : unresolved.length ? unresolved.join("; ") : `${specifiers.length} specifiers resolved: ${specifiers.join(", ")}`);
if (unresolved.length) {
  for (const f of failures) console.error(`FAIL: ${f}`);
  rmSync(work, { recursive: true, force: true });
  process.exit(1);
}

// ---- the page a host writes ----

// The README's snippet, twice: one explorer holding the page's address and
// its main landmark, one embedded beside it at the defaults. The engine is
// compiled once and handed to both, which is the sharing engineFor exists
// for, and the whole page is a host's, not this package's.
const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>a host page with two explorers</title>
<link rel="icon" href="data:,">
</head>
<body>
<header><h1>a host page</h1><div id="note"></div></header>
<main>
<section id="a" aria-label="the explorer this page gave its address to"></section>
<section id="b" aria-label="an explorer embedded beside it"></section>
</main>
<script type="module" src="./main.ts"></script>
</body>
</html>
`;
// A component of the host's own, with a <style>. The package ships none
// today, and the transform's stylesheet path is the half of it no component
// in this repository exercises — which is how it came to be broken without a
// gate noticing. A host writing a styled component is the case the transform
// is exported for, so it is the case this reads: the scoped rule has to reach
// the built stylesheet as a file, because the page is served under a policy
// with no 'unsafe-inline'.
const styled = `<script lang="ts">
	let { note }: { note: string } = $props();
</script>

<p class="host-note">{note}</p>

<style>
	.host-note {
		display: block;
	}
</style>
`;
const entry = `import { mount, unmount } from "svelte";

import { Explorer, compileEngine, engineFor } from "@cloudarq/explorer";
import HostNote from "./HostNote.svelte";
import "@cloudarq/explorer/tokens.css";
import "@cloudarq/explorer/explorer.css";

const engine = await engineFor(await compileEngine(new URL("cloudarq.wasm", document.baseURI)));
const a = mount(Explorer, { target: document.getElementById("a"), props: { engine, ownsAddress: true } });
mount(Explorer, { target: document.getElementById("b"), props: { engine } });
mount(HostNote, { target: document.getElementById("note"), props: { note: "a component of the host's own" } });

// The harness asks for the unmount through an event rather than through a
// name on globalThis, because what this page installs on globalThis is one
// of the things being read.
addEventListener("cloudarq:unmount-a", () => void unmount(a));
`;
writeFileSync(join(consumer, "index.html"), page);
writeFileSync(join(consumer, "main.ts"), entry);
writeFileSync(join(consumer, "HostNote.svelte"), styled);

const { svelte } = await import("./packages/explorer/vite.config.ts");
const { build } = await import("vite");
await build({
  root: consumer,
  base: "./",
  configFile: false,
  logLevel: "warn",
  plugins: [svelte()],
  resolve: { dedupe: ["svelte"], conditions: ["svelte", "browser"] },
  build: { outDir: "site", emptyOutDir: true, manifest: true, assetsInlineLimit: 0, cssCodeSplit: false, cssMinify: false, sourcemap: false, target: "es2022" },
});
const site = join(consumer, "site");
// the engine, copied onto the host's own origin the way the README says to
cpSync(resolved.get("@cloudarq/explorer/cloudarq.wasm"), join(site, "cloudarq.wasm"));
// An empty document on the same origin, for the globalThis comparison below:
// a long list of browser APIs is exposed only to a page whose origin the
// browser trusts, so about:blank carries some two hundred names fewer than
// this one and a difference measured against it would be a difference of
// origins rather than of the page.
writeFileSync(join(site, "blank.html"), "<!doctype html>\n<html lang=en><title>nothing</title>\n");
console.log(`  built a host page from ${resolve(tarball)}, mounting the component twice, into ${site}`);

// What the transform did with the host's <style>, read off what it built.
// The rule has to be in the stylesheet the page links, scoped by the class
// the compiler adds, and there has to be nothing between a <style> tag in the
// HTML: a page under a policy with no 'unsafe-inline' cannot wear an inline
// stylesheet, and a build that quietly inlined one would be a page that is
// styled here and bare where it is hosted.
{
  const stylesheets = readdirSync(join(site, "assets")).filter((f) => f.endsWith(".css"));
  const css = stylesheets.map((f) => readFileSync(join(site, "assets", f), "utf8")).join("\n");
  const html = readFileSync(join(site, "index.html"), "utf8");
  const scoped = css.match(/\.host-note\.svelte-[a-z0-9]+/);
  check("a host component's scoped stylesheet is built into the page's stylesheet", Boolean(scoped),
    scoped ? `${stylesheets.join(", ")} carries ${scoped[0]}`
      : stylesheets.length === 0 ? "the build emitted no stylesheet at all"
        : `${stylesheets.length} stylesheet(s) built, none of them carrying the host component's rule`);
  const inlined = /<style[^>]*>[^]*?<\/style>/.test(html);
  check("the built page carries no inline style", !inlined, inlined ? "the built HTML holds a <style> element" : `${html.length} bytes of built HTML read, no <style> among them`);
}

// ---- what the page does in Chrome ----

const server = await serveDirectory(site);
const browser = await launch(chromePath, { label: "cloudarq-consumer-check" });
const { errors, send, evaluate } = browser;
try {
  await send("Runtime.enable");
  await send("Log.enable");

  // The names a blank document has in this browser, so that what the page
  // adds is a difference and not a list somebody wrote down.
  // Each document is opened at a query of its own, so that a wait cannot be
  // answered by the one before it: the blank page and the host page are two
  // documents on one origin and a predicate about "the page" would be asked
  // of whichever is current. A wait that runs out throws rather than reading.
  await settleOn(browser, `${server.origin}/blank.html?blank`, "document.title === 'nothing'", { tries: 50 });
  const blank = await evaluate("Object.getOwnPropertyNames(globalThis)");

  await settleOn(browser, `${server.base}?host`, "document.querySelectorAll('[id$=answer-body] .sentence').length === 2", { tries: 100 });
  await sleep(200);

  console.log();
  console.log("── what the page installs on globalThis ──");
  const added = (await evaluate("Object.getOwnPropertyNames(globalThis)")).filter((name) => !blank.includes(name));
  // Svelte's own counter, which is how $props.id() stays unique across two
  // copies of the runtime on one page. It is the framework's name, set by
  // the framework, and it is named here rather than filtered silently.
  const framework = ["__svelte"];
  check("the page installs no name of its own on globalThis", added.every((name) => framework.includes(name)),
    `${added.length ? added.join(", ") : "nothing"} added over the ${blank.length} names a blank document has in this browser`);
  const glue = await evaluate(`["Go", "fs", "process", "admits", "explain"].filter(n => Object.prototype.hasOwnProperty.call(globalThis, n))`);
  check("the engine's glue leaves none of its names behind", glue.length === 0, glue.join(", ") || "none of Go, fs, process, admits, explain is an own property of globalThis");

  console.log();
  console.log("── two explorers on one page ──");
  const mounts = await evaluate("document.querySelectorAll('.panes').length");
  check("both explorers mounted", mounts === 2, `${mounts} explorers on the page`);

  const duplicated = await evaluate(`(() => {
    const seen = new Map();
    for (const el of document.querySelectorAll("[id]")) seen.set(el.id, (seen.get(el.id) || 0) + 1);
    return { ids: seen.size, twice: [...seen].filter(([, n]) => n > 1).map(([id, n]) => id + " ×" + n) };
  })()`);
  check("no element id is spelt twice", duplicated.ids > 0 && duplicated.twice.length === 0,
    duplicated.ids === 0 ? "the page rendered no element with an id, so nothing was compared" : duplicated.twice.length ? duplicated.twice.join(", ") : `${duplicated.ids} ids over the whole page, each of them once`);

  // Every reference an explorer makes by name, resolved: a label, a
  // described-by, a controls, and the explorer's own line and note
  // references. One that resolves into the other explorer is a control that
  // works the other document.
  const references = await evaluate(`(() => {
    const attributes = ["for", "aria-labelledby", "aria-describedby", "aria-controls", "aria-owns", "aria-details", "list", "headers", "data-ref"];
    const out = { read: 0, astray: [] };
    for (const explorer of document.querySelectorAll(".panes")) {
      for (const el of explorer.querySelectorAll("*")) {
        for (const attribute of attributes) {
          const value = el.getAttribute(attribute);
          if (!value) continue;
          for (const name of value.split(/\\s+/)) {
            out.read++;
            const target = document.getElementById(name);
            if (!target) { out.astray.push(el.tagName.toLowerCase() + "[" + attribute + "=" + name + "] -> nothing"); continue; }
            if (!explorer.contains(target)) out.astray.push(el.tagName.toLowerCase() + "[" + attribute + "=" + name + "] -> the other explorer");
          }
        }
      }
    }
    return out;
  })()`);
  check("every reference an explorer makes resolves inside that explorer", references.read > 0 && references.astray.length === 0,
    references.read === 0 ? "no reference was found in either explorer, so nothing was resolved" : references.astray.length ? references.astray.join("; ") : `${references.read} references read over both explorers`);

  const landmarks = await evaluate(`({ main: document.querySelectorAll("main").length, hosts: document.querySelectorAll("body > main").length })`);
  check("the page has one main landmark, the host's own", landmarks.main === 1 && landmarks.hosts === 1, `${landmarks.main} main elements, ${landmarks.hosts} of them the host's`);

  await evaluate(axeSource);
  const audit = await evaluate(`(async () => {
    const res = await axe.run(document, { resultTypes: ["violations"] });
    return { version: res.testEngine.version, passes: res.passes.length, violations: res.violations.map(v => v.id + " (" + v.impact + ") ×" + v.nodes.length + ": " + v.nodes.slice(0, 2).map(n => n.target.join(" ")).join(" | ")) };
  })()`);
  check("axe finds no violation on the two-mount page", audit.passes > 0 && audit.violations.length === 0,
    audit.passes === 0 ? "axe reported no rule passed, so it examined nothing" : audit.violations.length ? audit.violations.join(" || ") : `axe-core ${audit.version}, ${audit.passes} rules passed`);

  console.log();
  console.log("── the address, which one explorer holds ──");
  // The listing is what an explorer opens with, so the box is asked for
  // first; the pane renders it in the frame after the control is pressed.
  const typeInto = (into, text) => evaluate(`(async () => {
    const at = document.querySelector(${JSON.stringify(into)});
    if (!at.querySelector("textarea[name=policy]")) {
      at.querySelector("[id$=policy-edit]").click();
      await new Promise(r => requestAnimationFrame(r));
    }
    const box = at.querySelector("textarea[name=policy]");
    box.focus();
    box.value = ${JSON.stringify(text)};
    box.dispatchEvent(new InputEvent("input", { inputType: "insertFromPaste", bubbles: true }));
    return true;
  })()`);
  const readouts = () => evaluate(`({
    hash: location.hash,
    a: document.querySelector("#a [id$=policy-readout]").textContent,
    b: document.querySelector("#b [id$=policy-readout]").textContent,
  })`);

  const opened = await readouts();
  check("both explorers open with the same document", opened.a === opened.b && opened.a.includes("example 07"), `a reads "${opened.a}", b reads "${opened.b}"`);
  check("the explorer the host gave the address to wrote one", opened.hash.startsWith("#v1.aws."), opened.hash || "no fragment");

  // The share row offers the address as a link and as markdown. An explorer
  // that does not own the address has none to offer — href is assigned only
  // where the explorer writes the address — so a row rendered there would put
  // a bracketed sentence in front of a reader with nothing inside the
  // parentheses. The row belongs to the explorer that holds the address.
  const shareRows = await evaluate(`(() => {
    const of = at => {
      const row = document.querySelector(at + " [id$=share]");
      if (!row) return null;
      const field = row.querySelector("input");
      return { href: field.value, markdown: field.dataset.markdown };
    };
    return { a: of("#a"), b: of("#b") };
  })()`);
  check("only the explorer that holds the address renders a share row", shareRows.a !== null && shareRows.b === null,
    `the address's explorer renders ${shareRows.a ? "one" : "none"}, the embedded one renders ${shareRows.b ? "one" : "none"}`);
  check("the share row it renders offers the address rather than an empty link",
    Boolean(shareRows.a?.href.includes("#v1.aws.") && shareRows.a.markdown.includes(`](${shareRows.a.href})`)),
    shareRows.a ? `the field holds "${shareRows.a.href}" and the markdown "${shareRows.a.markdown.slice(0, 120)}"` : "no share row was rendered");

  const embedded = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}';
  await typeInto("#b", embedded);
  await sleep(400);
  const afterB = await readouts();
  check("the embedded explorer answers the document typed into it", afterB.b !== opened.b && afterB.b.includes("107 bytes"), afterB.b);
  check("the embedded explorer leaves the address alone", afterB.hash === opened.hash, `${opened.hash} became ${afterB.hash}`);
  check("the address's own explorer is untouched by the other's keystroke", afterB.a === opened.a, afterB.a);

  await typeInto("#a", embedded);
  await sleep(400);
  const afterA = await readouts();
  check("the explorer that holds the address moves it", afterA.hash !== opened.hash && afterA.hash.startsWith("#v1.aws."), `${opened.hash} became ${afterA.hash}`);

  console.log();
  console.log("── an explorer removed from the page ──");
  // A keystroke and a press of the clear link, then the explorer taken off
  // the page in the same turn, with an address write outstanding from each.
  // The two are scheduled differently and a teardown that stops one does not
  // thereby stop the other: a keystroke's write waits in a task and a frame
  // the teardown cancels, so it never starts; the link's write is already
  // past its await, where there is nothing left to cancel and the only thing
  // that stops it is the teardown having marked the explorer gone. A run
  // that drives the keystroke alone reads the cancelling and never reaches
  // the mark, and an explorer that stopped marking itself gone would move
  // the address about a second after it left the page.
  const before = afterA.hash;
  const other = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}';
  const driven = await evaluate(`(async () => {
    const at = document.querySelector("#a");
    if (!at.querySelector("textarea[name=policy]")) {
      at.querySelector("[id$=policy-edit]").click();
      await new Promise(r => requestAnimationFrame(r));
    }
    const box = at.querySelector("textarea[name=policy]");
    box.focus();
    box.value = ${JSON.stringify(other)};
    box.dispatchEvent(new InputEvent("input", { inputType: "insertFromPaste", bubbles: true }));
    const typed = box.value.length;
    const clear = at.querySelector("[id$=policy-clear]");
    clear?.click();
    dispatchEvent(new Event("cloudarq:unmount-a"));
    return { typed, pressed: Boolean(clear) };
  })()`);
  check("the unmount follows both a keystroke and a link that writes the address", driven.typed === other.length && driven.pressed, `the box held ${driven.typed} of ${other.length} bytes and the clear link was ${driven.pressed ? "pressed" : "not on the page"}`);
  await sleep(1000);
  const afterUnmount = await evaluate(`({ hash: location.hash, left: document.querySelector("#a").childElementCount, explorers: document.querySelectorAll(".panes").length })`);
  check("the explorer is off the page", afterUnmount.left === 0 && afterUnmount.explorers === 1, `#a holds ${afterUnmount.left} elements, ${afterUnmount.explorers} explorers left on the page`);
  check("an unmounted explorer writes no address", afterUnmount.hash === before, `the address was ${before} when it was unmounted and is ${afterUnmount.hash} a second later`);

  const stillThere = await evaluate(`document.querySelector("#b [id$=answer-body] .sentence") !== null`);
  check("the explorer beside it still answers", stillThere === true, `the embedded explorer ${stillThere ? "still holds" : "no longer holds"} a sentence`);
} finally {
  server.stop();
  await browser.stop();
  rmSync(work, { recursive: true, force: true });
}

console.log();
if (errors.length) {
  console.error(`consumer check: the host page raised ${errors.length} error(s) in Chrome:\n  ${errors.join("\n  ")}`);
  process.exit(1);
}
for (const f of failures) console.error(`FAIL: ${f}`);
console.log(`consumer check: ${checks} assertions read in Chrome over a page built from the tarball, ${failures.length} wrong`);
if (checks === 0 || failures.length > 0) process.exit(1);
