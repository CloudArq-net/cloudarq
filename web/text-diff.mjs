// The rendering differential: one page against the record of the page it
// replaced, the same words. The explorer was rewritten as a Svelte
// component, and the one thing the rewrite may not change is what a reader
// reads — the grant sentence, the claim table, the caveats, the witness, the
// readouts and the evidence rows. So the fixture was captured in Chrome off
// the page that was shipped before the component existed, and the page under
// test is driven through the same states and compared to it byte for byte.
// DOM structure is deliberately not compared: the component's markup differs
// and must be allowed to; the sentences are the product and they may not.
//
//   node web/text-diff.mjs capture <dist dir | url> <fixture.json>
//   node web/text-diff.mjs compare <dist dir | url> <fixture.json>
//
// The state list is every document of the conformance corpus — testdata/
// policies/*.json and testdata/grants/*/aws.json — in two views: the answer
// for the document, and the answer for a token no corpus grant admits on
// every claim, so explain's rejection paths are read as well as its admitted
// ones. Every state is addressed by the fragment the page itself spells, so
// the fragment grammar is under the same differential as the text.
//
// Exits non-zero on the first document that differs, and on a run that read
// no states at all: a differential over nothing is not a differential.
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

import { findChrome, launch, serveDirectory, settleOn } from "./chrome.mjs";

const [mode, target, fixturePath] = process.argv.slice(2);
if (!["capture", "compare"].includes(mode) || !target || !fixturePath) {
  console.error("usage: node web/text-diff.mjs capture|compare <dist dir | url> <fixture.json>");
  process.exit(2);
}

// the corpus, in the order readdir sorts it, so the fixture's keys are stable
const corpus = [
  ...readdirSync("testdata/policies").filter(f => f.endsWith(".json")).sort().map(f => join("testdata/policies", f)),
  ...readdirSync("testdata/grants").sort().map(d => join("testdata/grants", d, "aws.json")),
];

// One token, for every document: it carries the claims the corpus constrains
// and values no corpus grant admits, so explain answers with a refusal it has
// to spell rather than with a silence.
const foreignToken = JSON.stringify({
  iss: "https://token.actions.githubusercontent.com",
  aud: "https://github.com/acme",
  sub: "repo:acme-evil/infra:ref:refs/heads/main",
  repository_owner_id: "999999",
  repository_id: "1",
}, null, 2);

// Elements are addressed as [id$=name] rather than #name: the component
// spells every id under the instance that rendered it, so that two explorers
// on one page do not name the same element twice. The suffix is the part that
// does not depend on which instance rendered it.
const chromePath = findChrome();
if (!chromePath) {
  console.error("text diff: not run, no Chrome found; set CHROME to the browser's path");
  process.exit(1);
}

// The page under test is either a directory of built files, served here over
// loopback, or a URL somebody else is already serving. Both are the same
// argument because a harness that only knows one of them is two harnesses.
let server = null;
let base;
if (/^https?:\/\//.test(target)) {
  base = target;
} else {
  const dir = resolve(target);
  if (!existsSync(join(dir, "index.html"))) {
    console.error(`text diff: not run, ${join(dir, "index.html")} does not exist`);
    process.exit(1);
  }
  server = await serveDirectory(dir);
  base = server.base;
}

const browser = await launch(chromePath, { label: "cloudarq-text-diff" });
const { errors: thrown, send, evaluate } = browser;

// the fragment, spelt the way the page spells it: raw-deflate, base64url, no
// padding, the trailing empty field dropped
const base64url = bytes => Buffer.from(bytes).toString("base64url");
async function deflate(text) {
  if (!text) return "";
  const stream = new Blob([text]).stream().pipeThrough(new CompressionStream("deflate-raw"));
  return base64url(new Uint8Array(await new Response(stream).arrayBuffer()));
}
async function fragment(policy, token = "", view = "admits") {
  return "#" + ["v1", "aws", await deflate(policy), await deflate(token), view === "admits" ? "" : view].join(".").replace(/\.+$/, "");
}

// What is read from a state: every word a reader reads, in the order the page
// puts it there. Nothing here names a tag or a nesting — only the classes the
// stylesheet already keys on, which both pages must carry because both wear
// the same stylesheet.
const READ = `(() => {
  const all = (sel, root = document) => [...root.querySelectorAll(sel)];
  const text = el => el.textContent;
  const table = t => all("tr", t).map(tr => all("th, td", tr).map(text));
  return {
    hash: location.hash,
    policyReadout: (document.querySelector("[id$=policy-readout]") || {}).textContent ?? null,
    answerReadout: (document.querySelector("[id$=answer-readout]") || {}).textContent ?? null,
    grantHeads: all("[id$=answer-body] .grant-head").map(text),
    sentences: all("[id$=answer-body] .sentence").map(text),
    captions: all("[id$=answer-body] .sentence + .prose").map(text),
    terms: all("[id$=answer-body] table.terms").map(table),
    notes: all("[id$=answer-body] .notes li").map(text),
    witnesses: all("[id$=answer-body] .witness").map(w => ({
      heading: (w.querySelector("h4") || {}).textContent ?? null,
      token: (w.querySelector("pre.quote") || {}).textContent ?? null,
      caption: (w.querySelector(".prose") || {}).textContent ?? null,
    })),
    evidence: all("[id$=answer-body] details.evidence").map(d => ({
      summary: (d.querySelector("summary") || {}).textContent ?? null,
      open: d.open,
      pairs: all(".pairs > *", d).map(text),
      quoted: (d.querySelector("pre.quote") || {}).textContent ?? null,
    })),
    errors: all("[id$=answer-body] .error").map(text),
    bridge: (document.querySelector("[id$=answer-body] .bridge") || {}).textContent ?? null,
    listingLines: all("[id$=policy-body] .policy .l .src").map(text),
    marks: all("[id$=policy-body] button.mark").map(m => m.textContent + " " + m.getAttribute("aria-label")),
  };
})()`;

// Every state is opened at a query of its own, and settleOn will not read a
// state off a document at a different one: a navigation the browser could not
// make a document out of leaves the previous page up, answering the predicate
// below with the previous document's answer under this state's name. A wait
// that runs out throws rather than reading, because a differential is a
// comparison of two renderings and a page that never rendered is not one.
let opened = 0;
async function read(hash) {
  await settleOn(browser, `${base}?${++opened}${hash}`,
    "document.querySelector('[id$=answer-body]') !== null && document.querySelector('[id$=answer-body]').childElementCount > 0");
  await sleep(120);
  return evaluate(READ);
}

const states = [];
for (const file of corpus) {
  const policy = readFileSync(file, "utf8");
  states.push([`${file} · admits`, await fragment(policy)]);
  states.push([`${file} · token`, await fragment(policy, foreignToken, "token")]);
}

// A differential over nothing is not a differential. The count is asserted
// before the browser is asked to do anything, against the corpus rather than
// against the state list, so a state list that went empty cannot be read as a
// corpus that did.
if (corpus.length === 0 || states.length !== corpus.length * 2) {
  console.error(`text diff: not run, ${corpus.length} corpus documents produced ${states.length} states; two states per document is what this compares`);
  server?.stop();
  await browser.stop();
  process.exit(1);
}

const captured = {};
let differences = 0;
let notRead = "";
const expected = mode === "compare" ? JSON.parse(readFileSync(fixturePath, "utf8")) : null;

try {
  await send("Page.enable");
  await send("Runtime.enable");
  for (const [name, hash] of states) {
    const got = await read(hash);
    if (mode === "capture") { captured[name] = got; continue; }
    const want = expected[name];
    if (want === undefined) {
      differences++;
      console.error(`MISSING FROM THE FIXTURE: ${name}`);
      continue;
    }
    for (const key of Object.keys(want)) {
      const a = JSON.stringify(want[key]);
      const b = JSON.stringify(got[key]);
      if (a === b) continue;
      differences++;
      console.error(`DIFFERENT: ${name} · ${key}`);
      console.error(`  shipped: ${a.slice(0, 600)}`);
      console.error(`  built:   ${b.slice(0, 600)}`);
    }
  }
} catch (err) {
  notRead = err.message;
} finally {
  server?.stop();
  await browser.stop();
}

if (notRead) {
  console.error(`text diff: not completed, ${notRead}`);
  process.exit(1);
}

if (thrown.length) {
  console.error(`text diff: the page raised ${thrown.length} error(s) in Chrome:\n  ${thrown.join("\n  ")}`);
  process.exit(1);
}

if (mode === "capture") {
  writeFileSync(fixturePath, JSON.stringify(captured, null, 1) + "\n");
  const fields = Object.values(captured).reduce((n, s) => n + Object.keys(s).length, 0);
  console.log(`text diff: captured ${Object.keys(captured).length} states over ${corpus.length} corpus documents, ${fields} fields, into ${fixturePath}`);
  if (states.length === 0) process.exit(1);
  process.exit(0);
}

const fields = states.length * Object.keys(expected[states[0][0]] ?? {}).length;
console.log(`text diff: ${states.length} states over ${corpus.length} corpus documents, ${fields} fields compared, ${differences} differences`);
if (states.length === 0 || differences > 0) process.exit(1);
