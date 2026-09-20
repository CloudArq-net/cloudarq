// The page's behaviour, checked where it happens: in Chrome. The built page
// is served from the dist directory to a private headless Chrome and driven
// through the states a reader meets, and each state is read back from the
// DOM: the document the page opens with when the address carries nothing,
// the sentence a corrupt link gets, the engine's own sentence when it does
// not load, the statement a one-statement document opens with, where the
// keyboard lands after a paste, what a Deny grant's witness is headed, what
// a token view shares, that a document the parser reads as anomalous is
// answered, that a document nested past the bound is refused and the next
// one answered, and that nothing scrolls sideways at 400px.
//
// Five things are read in every state rather than in a named few, because
// each is stated in product/LAUNCH-STANDARD.md as a property of the page and
// not of one page of it: axe-core finds no violation; the finding sentence is
// the largest text and nothing outranks it; a state that shows a finding also
// shows the way on; the corpus documents and the disclosure are at the foot
// of the answer. The fold, the contrast ratios recorded beside the tokens,
// the listing's own quiet, the headers the page will be hosted under, what
// the page fetches and what it leaves in the browser are read once each,
// over the whole run.
//
//   node web/page-check.mjs <dist dir> <axe.min.js> [<pages emulator>]
//
// Exits non-zero on the first state that reads wrong, when axe or the pages
// emulator cannot be run, or when no Chrome can be found: a check that did
// not run is not a pass. Set CHROME to the browser's path when it is not at
// one of the usual ones.
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { extname, join, resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

const [dist, axePath, emulatorSpec] = process.argv.slice(2);
if (!dist || !axePath) {
  console.error("usage: node web/page-check.mjs <dist dir> <axe.min.js> [<pages emulator command>]");
  process.exit(2);
}
// The headers in web/dist/_headers are read back out of a response rather
// than out of the file, and the page is loaded under them: Cloudflare's own
// parser decides what a header file means, and a rule it silently drops is
// exactly the failure this is for. web/build.sh passes the pinned command
// and prints its digest; the default keeps the script runnable on its own.
const emulator = (emulatorSpec || "npx --yes wrangler@4.135.0").split(/\s+/);

// axe-core is a build-machine tool: web/build.sh fetches it at a pinned
// version, checks its digest and passes the path here. It is injected into
// each state through the debugger, never linked from the page, so the page
// still fetches nothing of its own.
let axeSource;
try {
  axeSource = readFileSync(axePath, "utf8");
} catch (err) {
  console.error(`axe: not run, ${axePath} could not be read (${err.message}); the accessibility audit is a gate, not an option`);
  process.exit(1);
}
if (axeSource.length < 100000) {
  console.error(`axe: not run, ${axePath} is ${axeSource.length} bytes, which is not the axe-core bundle`);
  process.exit(1);
}
// color-contrast is the one rule axe cannot decide here: it reports every
// pair it could not sample as incomplete. The pairs are computed instead by
// the design's contrast script, whose ratios are recorded beside the tokens,
// so that rule is read and any other incomplete rule fails the audit.
const contrastRule = "color-contrast";

function findChrome() {
  const candidates = [
    process.env.CHROME,
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
  ].filter(Boolean);
  for (const c of candidates) if (existsSync(c)) return c;
  for (const name of ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"]) {
    const found = spawnSync("which", [name], { encoding: "utf8" }).stdout.trim();
    if (found) return found;
  }
  return null;
}
const chromePath = findChrome();
if (!chromePath) {
  console.error("page check: not run, no Chrome found; set CHROME to the browser's path");
  process.exit(1);
}

// the built page over loopback; the engine can be withheld to see what the
// page says when it does not arrive
let withholdEngine = false;
const types = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".wasm": "application/wasm" };
const server = createServer((req, res) => {
  const path = join(resolve(dist), req.url === "/" ? "index.html" : req.url.split("?")[0]);
  if (!path.startsWith(resolve(dist)) || !existsSync(path) || statSync(path).isDirectory() || (withholdEngine && path.endsWith(".wasm"))) {
    res.writeHead(404).end();
    return;
  }
  res.writeHead(200, { "content-type": types[extname(path)] || "application/octet-stream" }).end(readFileSync(path));
});
await new Promise(ready => server.listen(0, "127.0.0.1", ready));
const base = `http://127.0.0.1:${server.address().port}/index.html`;

// extensions are off: one installed for every profile of the machine's Chrome
// injected a content script whose own exception was read as the page's
const port = 9600 + Math.floor(Math.random() * 300);
const profile = mkdtempSync(join(tmpdir(), "cloudarq-page-check-"));
const chrome = spawn(chromePath, [
  "--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-extensions", "--disable-gpu", "--hide-scrollbars",
  `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, "--window-size=1440,900", "about:blank",
], { stdio: "ignore" });

async function target() {
  for (let i = 0; i < 100; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
      const page = list.find(t => t.type === "page");
      if (page) return page.webSocketDebuggerUrl;
    } catch {}
    await sleep(100);
  }
  throw new Error("chrome did not come up");
}

const ws = new WebSocket(await target());
await new Promise(open => (ws.onopen = open));
let seq = 0;
const pending = new Map();
const errors = [];
// every request the page makes, over every state, so that the page's own
// sentence — everything runs in this page, nothing is sent anywhere — is a
// checked claim rather than a promise
const requested = new Set();
// A refused load is logged rather than thrown, so the console's own entries
// are kept apart: the run withholds the engine on purpose in one state and
// that 404 is not a fault. What is read from them is what the browser files
// under "security", which is where a content policy's refusals land.
const refusals = [];
ws.onmessage = m => {
  const msg = JSON.parse(m.data);
  if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
  if (msg.method === "Runtime.exceptionThrown") errors.push(msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text);
  if (msg.method === "Log.entryAdded" && msg.params.entry.source === "security") refusals.push(msg.params.entry.text);
  if (msg.method === "Network.requestWillBeSent") requested.add(msg.params.request.url);
  if (msg.method === "Network.webSocketCreated") requested.add(msg.params.url);
};
const send = (method, params = {}) => new Promise(resolve => { const id = ++seq; pending.set(id, resolve); ws.send(JSON.stringify({ id, method, params })); });
const evaluate = async expression => {
  const r = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
  if (r.result?.exceptionDetails) throw new Error(r.result.exceptionDetails.exception?.description || r.result.exceptionDetails.text);
  return r.result?.result?.value;
};

// the fragment for a state, spelt the way the page spells it
const base64url = bytes => Buffer.from(bytes).toString("base64url");
async function deflate(text) {
  if (!text) return "";
  const stream = new Blob([text]).stream().pipeThrough(new CompressionStream("deflate-raw"));
  return base64url(new Uint8Array(await new Response(stream).arrayBuffer()));
}
async function fragment(policy, token = "", view = "admits") {
  return "#" + ["v1", "aws", await deflate(policy), await deflate(token), view === "admits" ? "" : view].join(".").replace(/\.+$/, "");
}

// open loads one state in a fresh document (the query differs each time,
// so a fragment change is never a same-document navigation), waits for the
// engine and the fragment to have been read, and audits what it loaded: a
// state nobody audited is a state nobody checked.
let opened = 0;
async function open(name, hash, { width = 1440, height = 900, engine = true, mobile = false } = {}) {
  withholdEngine = !engine;
  await send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: mobile ? 2 : 1, mobile });
  await send("Page.navigate", { url: `${base}?${++opened}${hash}` });
  const settled = engine
    ? "typeof globalThis.admits === 'function' && document.querySelector('#answer-body').childElementCount > 0"
    : "document.querySelector('#answer-readout').textContent.length > 0";
  for (let i = 0; i < 100 && !(await evaluate(settled)); i++) await sleep(100);
  await sleep(150);
  await audit(`${name} at ${width}px`);
  // the way in, the way to read an answer and the way on are read wherever
  // the page is read, not in six named states: every state the engine reached
  // carries them
  if (!engine) return;
  await teaches(`${name} at ${width}px`);
  await sentenceIsLargest(`${name} at ${width}px`);
  await noDeadEnd(`${name} at ${width}px`);
}

let checks = 0;
const failures = [];
function check(name, ok, detail) {
  checks++;
  if (!ok) failures.push(`${name}: ${detail}`);
}

// audit runs axe-core over the state on screen. Zero violations, and the
// rules that passed are counted so that an audit of an empty document
// cannot read as a clean one.
let audits = 0;
let violations = 0;
let axeVersion = "";
const incompleteSeen = new Map();
async function audit(state) {
  await evaluate(axeSource);
  if ((await evaluate("typeof axe === 'object' && typeof axe.run === 'function'")) !== true) {
    console.error(`axe: not run, the bundle did not define axe.run in the page for ${state}`);
    process.exit(1);
  }
  const r = await evaluate(`(async () => {
    const res = await axe.run(document, { resultTypes: ["violations"] });
    return {
      version: res.testEngine.version,
      passes: res.passes.length,
      violations: res.violations.map(v => ({ id: v.id, impact: v.impact, tags: v.tags.join(","), nodes: v.nodes.length, where: v.nodes.slice(0, 3).map(n => n.target.join(" ")).join(" | ") })),
      incomplete: res.incomplete.map(i => [i.id, i.nodes.length]),
    };
  })()`);
  audits++;
  axeVersion = r.version;
  for (const [id, n] of r.incomplete) incompleteSeen.set(id, (incompleteSeen.get(id) || 0) + n);
  check(`axe passes rules on ${state}`, r.passes > 0, `axe reported ${r.passes} rules passed, so it examined nothing`);
  violations += r.violations.length;
  check(`axe finds no violation on ${state}`, r.violations.length === 0,
    r.violations.map(v => `${v.id} (${v.impact}; ${v.tags}) ×${v.nodes}: ${v.where}`).join(" || "));
  const undecided = r.incomplete.filter(([id]) => id !== contrastRule);
  check(`axe leaves nothing but ${contrastRule} undecided on ${state}`, undecided.length === 0,
    undecided.map(([id, n]) => `${id} ×${n}`).join(", "));
}
// The three corpus documents and the disclosure that says how to read an
// answer: the way in, and the key to what is on screen. They are the foot of
// the answer pane in every state, closed, so that no state is a dead end.
async function teaches(state) {
  const t = await evaluate(`({
    examples: document.querySelectorAll("a[data-example]").length,
    disclosures: document.querySelectorAll("details.how").length,
    opened: document.querySelectorAll("details.how[open]").length,
  })`);
  check(`${state}: the three corpus examples are on the page`, t.examples === 3, `${t.examples} example links`);
  check(`${state}: the disclosure is there and closed at load`, t.disclosures === 1 && t.opened === 0,
    `${t.disclosures} disclosures, ${t.opened} of them open at load`);
}

// product/LAUNCH-STANDARD.md §3: a first visit shows an evaluated example and
// its finding sentence above the fold, at 1280×720 and at 390×844. The whole
// sentence, not its first line: a sentence cut in half is not read.
async function sentenceAboveTheFold(state) {
  const fold = await evaluate(`(() => {
    const s = document.querySelector("#answer-body .sentence");
    if (!s) return null;
    const box = s.getBoundingClientRect();
    return { top: Math.round(box.top), bottom: Math.round(box.bottom), viewport: innerHeight };
  })()`);
  check(`${state}: the finding sentence is above the fold`,
    fold !== null && fold.top >= 0 && fold.bottom <= fold.viewport,
    fold === null ? "there is no sentence in the answer pane" : `the sentence runs ${fold.top}–${fold.bottom} px in a ${fold.viewport} px viewport`);
}

// a real key through the debugger, the path a reader's keyboard takes
async function pressEnter() {
  const key = { key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, nativeVirtualKeyCode: 13 };
  await send("Input.dispatchKeyEvent", { type: "keyDown", text: "\r", unmodifiedText: "\r", ...key });
  await send("Input.dispatchKeyEvent", { type: "keyUp", ...key });
}

const text = sel => evaluate(`(document.querySelector(${JSON.stringify(sel)}) || {}).textContent ?? null`);
const count = sel => evaluate(`document.querySelectorAll(${JSON.stringify(sel)}).length`);
const noSidewaysScroll = async name => {
  const widths = await evaluate("[document.documentElement.scrollWidth, document.body.scrollWidth, window.innerWidth]");
  check(`${name} at ${widths[2]}px does not scroll sideways`, widths[0] <= widths[2] && widths[1] <= widths[2], `scrollWidth ${widths[0]} (body ${widths[1]}) for a ${widths[2]}px viewport`);
};

const example = name => readFileSync(`testdata/grants/${name}/aws.json`, "utf8");
const policy03 = example("03-whole-organisation");
const policy07 = example("07-expressible-by-one-provider");
const rejected03 = JSON.stringify({ iss: "https://token.actions.githubusercontent.com", aud: "https://github.com/acme", sub: "repo:acme/infra:ref:refs/heads/main", repository_owner_id: "123456" }, null, 2);
const renamed07 = JSON.stringify({ iss: "https://token.actions.githubusercontent.com", aud: "sts.amazonaws.com", sub: "repo:acme/other:ref:refs/heads/main", repository_id: "456789" }, null, 2);
const deny = JSON.stringify({
  Version: "2012-10-17",
  Statement: [
    { Sid: "Allow", Effect: "Allow", Principal: { Federated: "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" }, Action: "sts:AssumeRoleWithWebIdentity", Condition: { StringEquals: { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" }, StringLike: { "token.actions.githubusercontent.com:sub": "repo:acme/*" } } },
    { Sid: "DenyPullRequests", Effect: "Deny", Principal: { Federated: "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" }, Action: "sts:AssumeRoleWithWebIdentity", Condition: { StringLike: { "token.actions.githubusercontent.com:sub": "repo:acme/*:pull_request" } } },
  ],
}, null, 2);
const denied = JSON.stringify({ iss: "https://token.actions.githubusercontent.com", aud: "sts.amazonaws.com", sub: "repo:acme/x:pull_request" });
const misspelt = '{"Version":"2012-10-17","Statement":[],"Statment":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}}';
const noStatements = '{"Version":"2012-10-17","Statement":[]}';
const scalarStatement = '{"Version": 2012, "Id": 5, "Statement": "nope"}';
const tooDeep = "{" + '"a":{'.repeat(1000) + "}".repeat(1001);

// the page is pasted into: the box's input event is the page's own path;
// a listing is opened for editing first
const paste = policy => evaluate(`(async () => {
  if (!document.querySelector("textarea[name=policy]")) {
    document.querySelector("#policy-edit").click();
    await new Promise(r => setTimeout(r, 50));
  }
  const box = document.querySelector("textarea[name=policy]");
  box.focus();
  box.value = ${JSON.stringify(policy)};
  box.dispatchEvent(new InputEvent("input", { inputType: "insertFromPaste", bubbles: true }));
  await new Promise(r => setTimeout(r, 200));
  const e = document.activeElement;
  return { active: e === document.body ? "body" : e.tagName + " " + (e.className || "") + " " + e.textContent.trim(), readout: document.querySelector("#policy-readout").textContent, answer: document.querySelector("#answer-readout").textContent, sentence: (document.querySelector("#answer-body .sentence") || {}).textContent ?? "", error: (document.querySelector("#answer-body .error") || {}).textContent ?? "" };
})()`);

// the grant sentence is the one piece of text on the page at the largest
// size: every .sentence computes to --text-l exactly, --text-l is at least
// the step the design sets, and nothing outside a sentence reaches it. A
// sentence's own descendants — the values it sets in code, a note's
// reference — are the sentence.
const sentenceStep = 20;
const hierarchy = () => evaluate(`(() => {
  const textL = parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--text-l"));
  const walk = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const rivals = [];
  for (let n = walk.nextNode(); n; n = walk.nextNode()) {
    const el = n.parentElement;
    if (!n.nodeValue.trim() || !el || el.closest(".sentence") || !el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) continue;
    const size = parseFloat(getComputedStyle(el).fontSize);
    if (size >= textL) rivals.push(el.tagName.toLowerCase() + (el.className ? "." + String(el.className).trim().split(/\\s+/).join(".") : "") + " at " + size + "px: " + n.nodeValue.trim().slice(0, 40));
  }
  const sentences = [...document.querySelectorAll(".sentence")].filter(s => s.checkVisibility()).map(s => parseFloat(getComputedStyle(s).fontSize));
  return { textL, sentences, rivals: rivals.slice(0, 5) };
})()`);
let headersRead = 0;
let emulatorUsed = "";
let sentencesRead = 0;
async function sentenceIsLargest(state) {
  const h = await hierarchy();
  sentencesRead += h.sentences.length;
  check(`${state}: every finding sentence is at the largest size`, h.sentences.every(s => s === h.textL) && h.textL >= sentenceStep,
    `--text-l is ${h.textL}px and the ${h.sentences.length} sentences compute to ${[...new Set(h.sentences)].join(", ")}px`);
  check(`${state}: nothing else on the page is that large`, h.rivals.length === 0, h.rivals.join(" || "));
}

// product/LAUNCH-STANDARD.md §3, no dead ends: a state that answers with a
// grant also shows the way on. A document the engine cannot read answers with
// no grant and is not a dead end either — the three corpus documents are under
// it — so the rule is read where there is a finding to act on.
async function noDeadEnd(state) {
  const shown = await evaluate(`({
    findings: document.querySelectorAll("#answer-body article.answer, #answer-body .token-answer").length,
    ways: document.querySelectorAll("#answer-body .bridge").length,
  })`);
  if (shown.findings === 0) return;
  check(`${state}: a state that shows a finding shows the way on`, shown.ways === 1,
    `${shown.findings} findings and ${shown.ways} lines out of the page`);
}

// The listing is the input and stays quiet: every line's source is ink-2,
// selected or not, and the selection is carried by the statement's mark and
// the rule beside its line numbers. Counted rather than sampled: a document
// of one statement opens with that statement selected, so one line of each
// kind read two lines of a listing where seventeen of twenty-two were the
// strongest block on the page.
const listingInk = () => evaluate(`(() => {
  const probe = document.body.appendChild(document.createElement("span"));
  const of = value => { probe.style.color = value; return getComputedStyle(probe).color; };
  const ink = of("var(--ink)"), ink2 = of("var(--ink-2)"), line = of("var(--line)");
  probe.remove();
  const sources = [...document.querySelectorAll(".policy .src")].map(n => getComputedStyle(n).color);
  const marks = [...document.querySelectorAll(".policy .mark")];
  const numbers = [...document.querySelectorAll(".policy .l[data-in] .ln")];
  const ruleOf = n => getComputedStyle(n).borderLeftColor;
  return {
    ink, ink2, line,
    lines: document.querySelectorAll(".policy .l").length,
    selectedLines: document.querySelectorAll(".policy .l[data-selected]").length,
    atInk: sources.filter(c => c === ink).length,
    atInk2: sources.filter(c => c === ink2).length,
    pressedMarks: marks.filter(m => m.getAttribute("aria-pressed") === "true").map(m => getComputedStyle(m).color),
    otherMarks: marks.filter(m => m.getAttribute("aria-pressed") !== "true").map(m => getComputedStyle(m).color),
    selectedRules: numbers.filter(n => n.closest(".l").hasAttribute("data-selected")).map(ruleOf),
    unselectedRules: numbers.filter(n => !n.closest(".l").hasAttribute("data-selected")).map(ruleOf),
  };
})()`);
// One reading of the listing, wherever a listing is on screen: no line of it
// is ink, every line is ink-2, and the selected statement is said with the
// mark and the rule instead.
let listingsRead = 0;
function listingIsQuiet(state, quiet) {
  listingsRead++;
  check(`${state}: the listing has lines to read`, quiet.lines > 0 && quiet.atInk + quiet.atInk2 === quiet.lines,
    `${quiet.lines} lines, ${quiet.atInk} at ink and ${quiet.atInk2} at ink-2`);
  check(`${state}: no line of the listing is at full ink`, quiet.atInk === 0,
    `${quiet.atInk} of ${quiet.lines} lines are ${quiet.ink}, which is --ink`);
  check(`${state}: the selected statement is marked, and its mark is the strong element`,
    quiet.selectedLines > 0 && quiet.pressedMarks.length > 0 && quiet.pressedMarks.every(c => c === quiet.ink) && quiet.otherMarks.every(c => c === quiet.ink2),
    `${quiet.selectedLines} selected lines, marks pressed ${JSON.stringify(quiet.pressedMarks)} against ${JSON.stringify([...new Set(quiet.otherMarks)])}`);
  check(`${state}: the rule beside the selected statement is ink and the others are not`,
    quiet.selectedRules.length > 0 && quiet.selectedRules.every(c => c === quiet.ink) && quiet.unselectedRules.every(c => c === quiet.line),
    `selected rules ${JSON.stringify([...new Set(quiet.selectedRules)])}, unselected ${JSON.stringify([...new Set(quiet.unselectedRules)])}`);
}

// ---- contrast ----
// product/LAUNCH-STANDARD.md §2: every pair at least 4.5:1 for body text,
// computed and recorded as a comment beside its token. The colours are read
// back out of Chrome rather than out of the file, so what is checked is what
// the page renders in that theme.
const textFloor = 4.5;
const inks = ["ink", "ink-2", "exact", "beyond", "unknown"];
const grounds = ["bg", "bg-2", "bg-mark"];
let contrastPairs = 0;
let requests = 0;

const palette = () => evaluate(`(() => {
  const probe = document.body.appendChild(document.createElement("span"));
  const read = name => { probe.style.color = "var(--" + name + ")"; return getComputedStyle(probe).color.match(/\\d+/g).slice(0, 3).map(Number); };
  const out = {};
  for (const name of ${JSON.stringify([...inks, ...grounds])}) out[name] = read(name);
  probe.remove();
  return out;
})()`);

const luminance = ([r, g, b]) => {
  const channel = c => (c / 255 <= 0.03928 ? c / 255 / 12.92 : ((c / 255 + 0.055) / 1.055) ** 2.4);
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
};
function contrastRatio(a, b) {
  const [lighter, darker] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (lighter + 0.05) / (darker + 0.05);
}

// The ratios as tokens.css writes them: `--ink: #1a1a1a;  /* on bg 17.40:1 ·
// bg-2 15.52:1 */`, per block. The two dark blocks are kept as text as well,
// because tokens.css says they must stay identical and nothing checked that.
function recordedRatios(css) {
  const blocks = { light: {}, dark: {} };
  const darkText = { media: [], pinned: [] };
  let into = null;
  for (const line of css.split("\n")) {
    if (/^:root\s*\{/.test(line)) into = "light";
    else if (/^@media \(prefers-color-scheme: dark\)/.test(line)) into = "media";
    else if (/^:root\[data-theme="dark"\]/.test(line)) into = "pinned";
    const declaration = line.match(/--([a-z0-9-]+):\s*(#[0-9a-f]{6});(.*)$/i);
    if (!declaration || into === null) continue;
    const [, name, , rest] = declaration;
    if (into !== "light") darkText[into].push(`${name}: ${declaration[2]};${rest.trim()}`);
    const written = [...rest.matchAll(/([a-z0-9-]+)\s+([\d.]+):1/g)].map(m => [m[1], m[2]]);
    if (written.length) blocks[into === "light" ? "light" : "dark"][name] = written;
  }
  return { ...blocks, darkMedia: darkText.media.join("\n"), darkPinned: darkText.pinned.join("\n") };
}

// ---- the header file, and a server that applies it ----

// The format Cloudflare Pages reads: a line at the margin opens a rule for
// the paths it matches, the indented lines under it are that rule's headers,
// and # is a comment. One rule, for every path, is what this page wants; a
// second would mean a file whose rules a reader has to resolve in their head.
function parseHeaders(text) {
  const rules = new Map();
  let current = null;
  for (const line of text.split("\n")) {
    if (!line.trim() || line.trim().startsWith("#")) continue;
    if (!/^\s/.test(line)) { current = new Map(); rules.set(line.trim(), current); continue; }
    const at = line.indexOf(":");
    if (current && at > 0) current.set(line.slice(0, at).trim(), line.slice(at + 1).trim());
  }
  check("the header file holds one rule, for every path", rules.size === 1 && rules.has("/*"), `it holds ${[...rules.keys()].join(", ") || "no rule"}`);
  return rules.get("/*") || new Map();
}

// The built page served the way it will be hosted. Cloudflare's own parser
// decides what the header file means — it drops a rule it cannot read and
// says so in one line — so the emulator is what is asked, not a reading of
// the file here. It is run in a directory of its own because it writes a
// .wrangler and a node_modules beside wherever it is started.
let emulatorProcess = null;
function stopEmulator() {
  if (!emulatorProcess) return;
  try { process.kill(-emulatorProcess.pid, "SIGKILL"); } catch { emulatorProcess.kill("SIGKILL"); }
  emulatorProcess = null;
}
async function servedHeaders(distDir) {
  const cwd = mkdtempSync(join(tmpdir(), "cloudarq-pages-"));
  const at = 8700 + Math.floor(Math.random() * 300);
  let log = "";
  // Its own process group: the command is a launcher that starts a wrangler
  // that starts a workerd, and a signal to the launcher alone leaves the
  // server running and this process waiting on a pipe it holds open.
  emulatorProcess = spawn(emulator[0], [...emulator.slice(1), "pages", "dev", resolve(distDir),
    "--ip", "127.0.0.1", "--port", String(at), "--compatibility-date=2025-10-01"], { cwd, detached: true, stdio: ["ignore", "pipe", "pipe"] });
  for (const stream of [emulatorProcess.stdout, emulatorProcess.stderr]) stream.on("data", d => { log += d; });
  // Pages redirects /index.html to /, so the page is asked for where it is
  // served from: a redirect's own headers are not the page's.
  const url = `http://127.0.0.1:${at}/`;
  let response = null;
  for (let i = 0; i < 300 && !response; i++) {
    try { response = await fetch(url); } catch { await sleep(200); }
  }
  if (!response) {
    console.error(`headers: not read, the pages emulator (${emulator.join(" ")}) did not serve ${url} within 60 s; the header set is a gate and cannot be skipped\n${log.slice(-800)}`);
    stopEmulator();
    process.exit(1);
  }
  return {
    url,
    headers: new Map([...response.headers]),
    rules: Number(log.match(/Parsed (\d+) valid header rule/)?.[1] ?? 0),
    log,
    stop: () => { stopEmulator(); rmSync(cwd, { recursive: true, force: true }); },
  };
}

// the bridge out of the page: one line under the last grant
const bridge = () => evaluate(`(() => {
  const b = document.querySelector(".bridge");
  if (!b) return null;
  const a = b.querySelector("a");
  return { text: b.textContent, href: a && a.getAttribute("href"), after: b.previousElementSibling && b.previousElementSibling.className };
})()`);

try {
  await send("Page.enable");
  await send("Runtime.enable");
  await send("Network.enable");
  await send("Log.enable");
  // Every change to the answer pane is recorded, so that a link naming a
  // document can be shown never to have flashed the default one first. The
  // mark is the Sid of the document the page opens with, read over the
  // pane's whole text: a prefix of it stops before the later half of an
  // answer, and the pattern the default's grant is about — acme/infra — is
  // also the subject of 03's witness, so a record that read either would
  // pass on a flash and fail on a document that merely mentions it.
  await send("Page.addScriptToEvaluateOnNewDocument", { source: `
    // what the content policy refused, as the document itself saw it
    window.__refused = [];
    addEventListener("securitypolicyviolation", e => window.__refused.push(e.effectiveDirective + " refused " + (e.blockedURI || "an inline " + e.violatedDirective)));
    window.__shown = [];
    new MutationObserver(() => {
      const body = document.querySelector("#answer-body");
      if (!body) return;
      const text = body.textContent;
      window.__shown.push({ chars: text.length, opening: text.includes("GitHubForAllValues"), head: text.trim().slice(0, 80) });
    }).observe(document, { childList: true, subtree: true, characterData: true });
  ` });

  // an address carrying nothing: the page opens answering, on the document
  // it names, at the address a reader can copy
  const default07 = await fragment(policy07);
  await open("the default document", "");
  check("the page opens answering", (await count("#answer-body .sentence")) === 1, `${await count("#answer-body .sentence")} sentences in the answer pane`);
  check("the default document is named as an example", (await text("#policy-readout")) === "aws trust policy · 634 bytes · 1 statement · example 07", await text("#policy-readout"));
  check("the default writes its own address", (await evaluate("location.hash")) === default07, `${await evaluate("location.hash")} for a page opened with no fragment`);
  const openedWithNothing = await evaluate("[document.querySelector('#policy-body').innerHTML, document.querySelector('#answer-body').innerHTML]");
  check("the head names the paste control over a corpus document", (await text("#policy-clear")) === "paste your own" && (await text("#policy-edit")) === "edit" && (await evaluate("document.querySelector('#policy-edit').hidden")) === false, `clear reads "${await text("#policy-clear")}", edit reads "${await text("#policy-edit")}" hidden ${await evaluate("document.querySelector('#policy-edit').hidden")}`);
  // the empty state is a state like any other and has an address of its own;
  // only an absent fragment means the document the page opens with
  check("the paste control carries the empty state's own address", (await evaluate("document.querySelector('#policy-clear').getAttribute('href')")) === "#v1.aws", await evaluate("document.querySelector('#policy-clear').getAttribute('href')"));
  await sentenceAboveTheFold("the default document at 1440×900");
  listingIsQuiet("the default document at 1440×900", await listingInk());
  const opening = await bridge();
  check("the bridge sits under the last grant", opening !== null && opening.after === "answer" && opening.href === "https://github.com/CloudArq-net/cloudarq", JSON.stringify(opening));

  // the same document reached by its link renders identically
  await open("07 admits", default07);
  const openedByLink = await evaluate("[document.querySelector('#policy-body').innerHTML, document.querySelector('#answer-body').innerHTML]");
  check("the default renders as its own shared link does", openedWithNothing[0] === openedByLink[0] && openedWithNothing[1] === openedByLink[1],
    `the panes differ: policy ${openedWithNothing[0].length} against ${openedByLink[0].length} bytes, answer ${openedWithNothing[1].length} against ${openedByLink[1].length}`);

  // a link naming another document wins over the default, and is never
  // preceded on screen by it
  const whole = await fragment(policy03);
  await open("03 admits", whole);
  const shown = await evaluate("window.__shown");
  const flashes = shown.filter(s => s.opening);
  check("a link naming a document never flashes the default one", shown.length > 0 && flashes.length === 0,
    `${shown.length} renderings of the answer pane, ${flashes.length} of them carrying the opening document's statement: ${flashes.slice(0, 2).map(s => s.head).join(" | ")}`);
  check("the record of what was shown read whole answers", shown.some(s => s.chars > 400),
    `the largest rendering recorded was ${Math.max(0, ...shown.map(s => s.chars))} characters, so a flash later in the pane would not have been seen`);

  // the fold, at the two viewports the launch standard names
  await open("the default document", "", { width: 1280, height: 720 });
  await sentenceAboveTheFold("the default document at 1280×720");
  await open("the default document", "", { width: 390, height: 844, mobile: true });
  await sentenceAboveTheFold("the default document at 390×844");

  // The paste control, worked the way a keyboard works it. It empties both
  // panes, leaves the empty state's own address, and puts the keyboard in
  // the box it exists to produce: a control that hides itself under the
  // reader's focus drops them back at the top of the page.
  await open("the default document", "");
  await evaluate("document.querySelector('#policy-clear').focus()");
  check("the paste control is in the tab order", (await evaluate("document.activeElement.id")) === "policy-clear", await evaluate("document.activeElement.tagName + '#' + document.activeElement.id"));
  await pressEnter();
  await sleep(250);
  const emptied = await evaluate(`({
    hash: location.hash,
    active: document.activeElement.tagName + (document.activeElement.name ? "[name=" + document.activeElement.name + "]" : "#" + document.activeElement.id),
    boxes: document.querySelectorAll("textarea[name=policy]").length,
    value: (document.querySelector("textarea[name=policy]") || {}).value,
    sentences: document.querySelectorAll(".sentence").length,
    readout: document.querySelector("#policy-readout").textContent,
  })`);
  await audit("the paste state at 1440px");
  check("Enter on the paste control leaves an empty box", emptied.boxes === 1 && emptied.value === "", JSON.stringify(emptied));
  check("Enter on the paste control leaves the keyboard in that box", emptied.active === "TEXTAREA[name=policy]", `the keyboard landed on ${emptied.active}`);
  check("Enter on the paste control leaves no answer", emptied.sentences === 0 && emptied.readout === "nothing pasted", JSON.stringify(emptied));
  check("Enter on the paste control leaves the empty state's address", emptied.hash === "#v1.aws", emptied.hash);
  check("the empty state has no bridge", (await bridge()) === null, JSON.stringify(await bridge()));
  check("the empty state teaches", (await count(".teach")) === 1 && (await count("[data-copy=nothing]:not([hidden])")) === 1, `${await count(".teach")} teach blocks`);
  await teaches("the paste state at 1440px");
  check("the share row says there is nothing to share", (await evaluate("(() => { document.querySelector('#share-toggle').click(); return document.querySelector('#share-note').textContent; })()")) === "Nothing to share yet: nothing is pasted.", await text("#share-note"));
  await audit("the share row open at 1440px");

  // the empty state
  await open("the empty state", "#v1.aws");
  check("the empty state teaches", (await count(".teach")) === 1, "no .teach");
  check("the empty state says nothing of left or right", !/on the (left|right)\b/.test(await evaluate("document.body.innerText")), "the copy places a pane left or right, which is false when the panes stack");
  const landed = await paste(policy03);
  check("a paste into the empty box becomes the listing", landed.readout === "aws trust policy · 626 bytes · 1 statement · example 03", landed.readout);
  check("the keyboard lands on the first statement's mark", landed.active === "BUTTON mark [0]", `active element ${landed.active}`);
  const deep = await paste(tooDeep);
  check("a document nested past the bound is refused, not trapped", deep.sentence === "This is not a trust policy the engine can read." && deep.error === "the document is nested 1001 levels deep; the engine reads up to 1000 levels, and level 1001 opens at byte 5000", `${deep.sentence}: ${deep.error}`);
  await teaches("a document the engine cannot read");
  // a state reached by typing rather than by an address is audited where it
  // is reached: open() audits what it loads, and nothing loads this one
  await audit("a document the engine cannot read at 1440px");
  const recovered = await paste(policy03);
  await audit("the document after a refusal at 1440px");
  check("the engine answers the next document after a refusal", recovered.answer === "1 grant · exact", recovered.answer);

  // a link cut short when it was copied
  await open("a corrupt link", whole.slice(0, 200));
  const unreadable = await text("[data-copy=unreadable-link]:not([hidden])");
  check("a corrupt link says the link could not be read", unreadable !== null && unreadable.includes("this page could not read"), `sentence: ${unreadable}`);
  check("a corrupt link never blames the engine", !(await text("#answer-readout")).includes("engine did not load"), await text("#answer-readout"));
  check("a corrupt link loads nothing", (await count("textarea[name=policy]")) === 1 && (await text("#policy-readout")) === "nothing pasted", await text("#policy-readout"));
  await open("a link of another version", "#v2.aws.abc");
  check("a link of another version says so", ((await text("[data-copy=unreadable-link]:not([hidden])")) || "").includes("this page reads v1"), await text("[data-copy=unreadable-link]"));

  // the engine does not arrive
  await open("03 admits without the engine", whole, { engine: false });
  check("the engine's own load failure keeps its own sentence", (await text("#answer-readout")).startsWith("the engine did not load: "), await text("#answer-readout"));

  // one statement opens selected, and the toggle is a button
  await open("03 admits", whole);
  check("a one-statement document opens with its statement selected", (await count("button.mark[data-stmt='0'][aria-pressed='true']")) === 1 && (await count(".grant-head .stmt[aria-pressed='true']")) === 1 && (await count(".l[data-selected]")) === 17, `${await count("[aria-pressed='true'][data-stmt]")} pressed, ${await count(".l[data-selected]")} lines selected`);
  listingIsQuiet("03 admits at 1440×900", await listingInk());
  check("the edit toggle is a button", (await evaluate("document.querySelector('#policy-edit').tagName")) === "BUTTON", await evaluate("document.querySelector('#policy-edit').outerHTML"));
  await evaluate("document.querySelector('#policy-edit').click()");
  check("edit shows the document in the box", (await count("textarea[name=policy]")) === 1 && (await text("#policy-edit")) === "listing", await text("#policy-edit"));
  await audit("the edit state at 1440px");
  await evaluate("document.querySelector('#policy-edit').click()");
  check("listing shows the document as lines", (await count(".policy .l")) === 22 && (await text("#policy-edit")) === "edit", `${await count(".policy .l")} lines`);

  // the evidence body of a closed details is written when it opens, and
  // while it is open a keystroke moves it with the statement
  const statementBytes = policy03.slice(50, 619);
  await evaluate("document.querySelector('details.evidence summary').click()");
  await sleep(50);
  const evidence = async () => evaluate("[document.querySelector('details.evidence').open, document.querySelector('details.evidence summary').textContent, document.querySelector('details.evidence dd').textContent, document.querySelector('details.evidence pre').textContent]");
  let [isOpen, summary, documentRow, quoted] = await evidence();
  check("an opened evidence body quotes the statement", isOpen && summary.startsWith("evidence · statement[0] · 569 bytes at offset 50") && documentRow.startsWith("626 bytes as pasted, 22 lines") && quoted === statementBytes, `${summary} | ${documentRow.slice(0, 40)} | ${quoted.length} bytes quoted`);
  // a space after the opening brace moves every offset and no line, so
  // the grant reads the same and its article is kept
  await paste("{ " + policy03.slice(1));
  [isOpen, summary, documentRow, quoted] = await evidence();
  check("a keystroke moves an open evidence body", isOpen && summary.startsWith("evidence · statement[0] · 569 bytes at offset 51") && documentRow.startsWith("627 bytes as pasted, 22 lines") && quoted === statementBytes, `${summary} | ${documentRow.slice(0, 40)}`);
  await evaluate("document.querySelector('details.evidence summary').click()");
  await paste("{  " + policy03.slice(1));
  [isOpen, summary, documentRow] = await evidence();
  check("a closed evidence keeps its summary current and its body until opened", !isOpen && summary.startsWith("evidence · statement[0] · 569 bytes at offset 52") && documentRow.startsWith("627 bytes as pasted, 22 lines"), `${summary} | ${documentRow.slice(0, 40)}`);
  await evaluate("document.querySelector('details.evidence summary').click()");
  await sleep(50);
  [isOpen, summary, documentRow, quoted] = await evidence();
  check("opening a stale evidence writes its body", isOpen && documentRow.startsWith("628 bytes as pasted, 22 lines") && quoted === statementBytes, `${summary} | ${documentRow.slice(0, 40)} | ${quoted.length} bytes quoted`);

  // The answer is computed in the keystroke that asks for it, not in the
  // frame after it: the browser's next frame is up to one display interval
  // away, and an answer that waits for it lands a frame late for no reason.
  // The sentence is read with nothing awaited between the input event and
  // the reading, so only a re-evaluation inside the keystroke can have
  // written it.
  await open("03 admits", whole);
  await evaluate("document.querySelector('#policy-edit').click()");
  await sleep(100);
  const answered = await evaluate(`(() => {
    const box = document.querySelector("textarea[name=policy]");
    const sentence = () => (document.querySelector("#answer-body .sentence") || {}).textContent ?? "";
    const readout = () => document.querySelector("#policy-readout").textContent;
    const before = { sentence: sentence(), readout: readout() };
    if (!before.sentence.includes("repository_owner_id")) throw new Error("the document before the keystroke is not the one this reads: " + before.sentence.slice(0, 80));
    box.value = ${JSON.stringify(example("06-unconstrained"))};
    box.dispatchEvent(new InputEvent("input", { inputType: "insertText", bubbles: true }));
    return { before, after: { sentence: sentence(), readout: readout() } };
  })()`);
  check("the answer is computed in the keystroke, not in the frame after it",
    answered.after.sentence.length > 0 && !answered.after.sentence.includes("repository_owner_id") && answered.after.readout.endsWith("example 06"),
    `in the keystroke the readout read "${answered.after.readout}" and the sentence read "${answered.after.sentence.slice(0, 90)}"`);

  // Three keystrokes inside one frame are two re-evaluations, not three: the
  // first is answered where it is heard and the last is answered in the
  // frame it asked for, and the ones in between are overtaken. That bound on
  // the work one frame can be asked to do is what the frame callback used to
  // give unconditionally.
  const inOneFrame = await evaluate(`(async () => {
    const box = document.querySelector("textarea[name=policy]");
    const engine = globalThis.admits;
    let calls = 0;
    globalThis.admits = p => { calls++; return engine(p); };
    // a space before the document's first brace: JSON ignores it, so each
    // keystroke is a readable document one byte longer than the last
    const base = box.value.trimStart();
    const type = n => {
      box.value = " ".repeat(n) + base;
      box.dispatchEvent(new InputEvent("input", { inputType: "insertText", bubbles: true }));
    };
    type(1); type(2); type(3);
    const inTheKeystrokes = calls;
    await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)));
    globalThis.admits = engine;
    return { inTheKeystrokes, byTheFrame: calls, bytes: document.querySelector("#policy-readout").textContent };
  })()`);
  check("three keystrokes inside one frame are two re-evaluations",
    inOneFrame.inTheKeystrokes === 1 && inOneFrame.byTheFrame === 2,
    `${inOneFrame.inTheKeystrokes} re-evaluation(s) in the keystrokes and ${inOneFrame.byTheFrame} by the end of the frame`);
  check("the last of them is the one the page ends up showing", inOneFrame.bytes === "aws trust policy · 444 bytes · 1 statement", inOneFrame.bytes);

  // the token view: a constraint value is code in the exact colour
  await open("03 with the rejected token", await fragment(policy03, rejected03, "token"));
  const inToken = await bridge();
  check("the token view carries the bridge too", inToken !== null && inToken.href === "https://github.com/CloudArq-net/cloudarq", JSON.stringify(inToken));
  check("the token view carries the teaching block under the bridge", (await count(".teach")) === 1 && (await evaluate("document.querySelector('.teach').previousElementSibling.className")) === "bridge prose", `${await count(".teach")} teach blocks, after ${await evaluate("(document.querySelector('.teach')||{}).previousElementSibling?.className")}`);
  check("the rejected token's sentence sets the grant's value as code in the exact colour", (await evaluate("[...document.querySelectorAll('.token-answer .sentence code.v-exact')].map(c => c.textContent)")).includes("sts.amazonaws.com"), await evaluate("document.querySelector('.token-answer .sentence').innerHTML"));
  await open("07 with the renamed token", await fragment(policy07, renamed07, "token"));
  const renamed = await text(".token-answer .sentence");
  check("the unevaluated claim's caveat is quoted as a sentence of its own", renamed.includes("restricts. Whether it excludes the token is not decided here.") && !renamed.includes("restricts, so whether"), renamed);
  await open("07 admits", await fragment(policy07));
  const caption = await text(".witness .prose");
  check("the witness caption does not call an unevaluated claim unconstrained", caption.includes("sub is not shown because it was not evaluated") && !/\bsub\b[^.]*unconstrained/.test(caption), caption);

  // a Deny grant's witness, and what a token view shares
  await open("a Deny policy", await fragment(deny));
  check("a document of the reader's own is answered grant by grant", (await count("article.answer")) === 2, `${await count("article.answer")} articles for a two-statement document`);
  check("a document of the reader's own still gets the bridge", (await bridge()) !== null, "no bridge under the last grant");
  check("a Deny grant's witness is headed by what the grant does", (await evaluate("[...document.querySelectorAll('.witness h4')].map(h => h.textContent)")).join(" | ") === "a token this grant admits | a token this grant refuses", await evaluate("[...document.querySelectorAll('.witness h4')].map(h => h.textContent).join(' | ')"));
  // a document of more than one statement opens with none selected, so the
  // listing is read again once a mark has been pressed: the selection's own
  // marks are what has to carry it
  check("a document of two statements opens with neither selected", (await count(".l[data-selected]")) === 0, `${await count(".l[data-selected]")} lines selected before anything is pressed`);
  await evaluate("document.querySelector(\"button.mark[data-stmt='1']\").click()");
  await sleep(50);
  listingIsQuiet("a Deny policy with its second statement selected", await listingInk());
  await open("a Deny policy with a denied token", await fragment(deny, denied, "token"));
  await evaluate("document.querySelector('#share-toggle').click()");
  const markdown = await evaluate("document.querySelector('#share-url').dataset.markdown");
  check("a token view shares the policy's answer for the token", markdown.startsWith("[Refused by grant 2, though grant 1 admits it.]("), markdown.slice(0, 80));
  await noSidewaysScroll("the token view of a Deny policy");

  // a document the engine reads and finds nobody in: an answer, and still a
  // way on
  await open("a document with no statement", await fragment(noStatements));
  check("a document with no statement says nobody is named", (await text("#answer-readout")) === "0 grants · nobody is named" && (await count("article.answer")) === 0, `${await text("#answer-readout")}, ${await count("article.answer")} articles`);

  // documents the parser reads as anomalous are answered, not refused
  for (const [name, doc] of [["a misspelt member", misspelt], ["a scalar Statement", scalarStatement]]) {
    await open(name, await fragment(doc));
    check(`${name} is answered with its anomaly`, (await text("#answer-readout")) === "1 grant · upper bound · 1 caveat" && (await count("article.answer")) === 1 && (await count(".notes li")) >= 1, `${await text("#answer-readout")}, ${await count("article.answer")} articles`);
  }

  // nothing scrolls sideways at 400px
  const narrow = { width: 400, height: 800 };
  for (const [name, hash] of [
    ["the empty state", "#v1.aws"],
    ["a corrupt link", whole.slice(0, 200)],
    ["03 admits", whole],
    ["03 with the rejected token", await fragment(policy03, rejected03, "token")],
    ["07 admits", await fragment(policy07)],
    ["07 with the renamed token", await fragment(policy07, renamed07, "token")],
    ["a misspelt member", await fragment(misspelt)],
  ]) {
    await open(name, hash, narrow);
    await noSidewaysScroll(name);
  }

  // Printed, the listing is the exhibit and nothing may be cut off: the cap
  // that keeps the answer on screen when the panes stack is a screen rule,
  // and an A4 page is 794 px wide, which is inside that breakpoint.
  await open("07 admits", default07, { width: 794, height: 1123 });
  await send("Emulation.setEmulatedMedia", { media: "print" });
  await sleep(100);
  const printed = await evaluate(`(() => {
    const listing = document.querySelector(".policy");
    const style = getComputedStyle(listing);
    return { maxHeight: style.maxHeight, overflowY: style.overflowY, height: Math.round(listing.getBoundingClientRect().height), lines: document.querySelectorAll(".l").length, scrollHeight: listing.scrollHeight };
  })()`);
  check("the whole listing is printed", printed.maxHeight === "none" && printed.height >= printed.scrollHeight,
    `the listing computes to max-height ${printed.maxHeight}, ${printed.height} px tall against ${printed.scrollHeight} px of ${printed.lines} lines`);
  await send("Emulation.setEmulatedMedia", { media: "" });

  // Contrast, against the colours Chrome renders rather than against the
  // hex in the file: every ratio written beside a token in tokens.css is
  // recomputed from the token's own rendered value, in the theme that block
  // governs, and each must be the number written and at least the floor for
  // body text. A pair nobody wrote down is a pair nobody measured, so every
  // ink in every block must carry its ratios.
  const recorded = recordedRatios(readFileSync("web/tokens.css", "utf8"));
  check("the two dark blocks are the same declarations", recorded.darkMedia === recorded.darkPinned,
    `the media query and [data-theme="dark"] differ:\n${recorded.darkMedia}\n${recorded.darkPinned}`);
  let pairs = 0;
  // the third pass pins dark with the theme control while the system asks for
  // light, which is the only way the [data-theme="dark"] block is ever read
  for (const { where, system, pin, block } of [
    { where: "light", system: "light", pin: false, block: recorded.light },
    { where: "dark by the system", system: "dark", pin: false, block: recorded.dark },
    { where: "dark by the theme control", system: "light", pin: true, block: recorded.dark },
  ]) {
    await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: system }] });
    await open(where, default07);
    if (pin) {
      await evaluate(`document.documentElement.dataset.theme = "dark"`);
      await sleep(50);
    }
    const rendered = await palette();
    for (const ink of inks) {
      const written = block[ink];
      check(`${where}: ${ink} carries its ratios in tokens.css`, written && written.length > 0, `no ratio is written beside --${ink}`);
      for (const [ground, saidRatio] of written || []) {
        const measured = contrastRatio(rendered[ink], rendered[ground]);
        pairs++;
        check(`${where}: ${ink} on ${ground} is written as measured`, measured.toFixed(2) === saidRatio,
          `tokens.css says ${saidRatio}:1, Chrome renders ${rendered[ink]} on ${rendered[ground]} at ${measured.toFixed(2)}:1`);
        check(`${where}: ${ink} on ${ground} reaches the floor for body text`, measured >= textFloor,
          `${measured.toFixed(2)}:1, under ${textFloor}:1`);
      }
    }
  }
  check("every pair recorded beside a token was measured", pairs > 0, "no ratio was read out of tokens.css, so nothing was compared");
  contrastPairs = pairs;

  // ---- the headers the hosted page is served under ----
  // product/LAUNCH-STANDARD.md §4, and the one row on it that cannot be met
  // by a file: the set is asserted where it is declared, in web/dist/_headers,
  // and again in the response Cloudflare's own server built from that file,
  // and then the page is loaded under it. The emulator adds two headers of
  // its own in dev, so the declaration is what is read for content and the
  // response is what proves the declaration was applied at all.
  const headersFile = join(resolve(dist), "_headers");
  check("the hosted page carries a header file", existsSync(headersFile), `${headersFile} does not exist`);
  const declared = existsSync(headersFile) ? parseHeaders(readFileSync(headersFile, "utf8")) : new Map();
  const required = {
    "Content-Security-Policy": csp => {
      const tokens = csp.split(";").map(d => d.trim().split(/\s+/));
      const directive = name => (tokens.find(t => t[0] === name) || []).slice(1).join(" ");
      const unsafe = tokens.flat().filter(t => t === "'unsafe-inline'" || t === "'unsafe-eval'");
      if (unsafe.length) return `carries ${unsafe.join(" and ")}`;
      for (const [name, value] of [["default-src", "'none'"], ["script-src", "'self' 'wasm-unsafe-eval'"], ["base-uri", "'none'"], ["form-action", "'none'"], ["frame-ancestors", "'none'"]]) {
        if (directive(name) !== value) return `${name} is "${directive(name) || "absent"}", not "${value}"`;
      }
      return "";
    },
    "Strict-Transport-Security": hsts => {
      const age = Number(hsts.match(/max-age=(\d+)/)?.[1]);
      if (!(age >= 31536000)) return `max-age is ${hsts.match(/max-age=(\d+)/)?.[1] ?? "absent"}, under a year`;
      if (!/includeSubDomains/.test(hsts) || !/preload/.test(hsts)) return "it does not ask for includeSubDomains and preload";
      return "";
    },
    "X-Content-Type-Options": v => (v === "nosniff" ? "" : `it reads "${v}"`),
    "Referrer-Policy": v => (v === "no-referrer" ? "" : `it reads "${v}"`),
    "Permissions-Policy": v => {
      const features = v.split(",").map(f => f.trim()).filter(Boolean);
      const allowed = features.filter(f => !/^[a-z-]+=\(\)$/.test(f));
      if (allowed.length) return `${allowed.join(", ")} ${allowed.length === 1 ? "is" : "are"} not denied`;
      return features.length >= 20 ? "" : `it names ${features.length} features`;
    },
  };
  for (const [name, meets] of Object.entries(required)) {
    const value = declared.get(name);
    check(`_headers declares ${name}`, value !== undefined, "it is not in the file");
    if (value !== undefined) check(`_headers declares ${name} as the launch standard asks`, meets(value) === "", `${meets(value)}: ${value}`);
  }

  // the same headers, read out of the response Cloudflare's own server built
  const served = await servedHeaders(dist);
  check("the pages emulator parsed the header file", served.rules >= 1, `it reported ${served.rules} valid header rules: ${served.log.slice(-400)}`);
  for (const name of Object.keys(required)) {
    const want = declared.get(name);
    const got = served.headers.get(name.toLowerCase());
    check(`the served response carries ${name} as the file declares it`, want !== undefined && got === want, `served "${got ?? "nothing"}"`);
  }

  // and the page under them: an engine that will not compile under the
  // policy, or a stylesheet the policy refuses, is a hosted page that does
  // not work, which no reading of the file would have shown
  await send("Page.navigate", { url: served.url });
  for (let i = 0; i < 100 && !(await evaluate("typeof globalThis.admits === 'function' && document.querySelector('#answer-body .sentence') !== null")); i++) await sleep(100);
  await sleep(200);
  const underPolicy = await evaluate(`({ refused: window.__refused, sentence: (document.querySelector("#answer-body .sentence") || {}).textContent ?? null, hash: location.hash })`);
  check("the page evaluates under its own content policy", underPolicy.sentence !== null && underPolicy.hash.startsWith("#v1.aws."),
    `the answer pane holds ${underPolicy.sentence === null ? "no sentence" : "a sentence"} at ${underPolicy.hash || "no fragment"}`);
  check("the content policy refuses nothing the page does", underPolicy.refused.length === 0 && refusals.length === 0,
    [...underPolicy.refused, ...refusals].join(" || "));
  await audit("the page under its own content policy at 1440px");
  await sentenceIsLargest("the page under its own content policy at 1440px");
  headersRead = Object.keys(required).length;
  emulatorUsed = `${emulator.join(" ")}, ${served.rules} header rule${served.rules === 1 ? "" : "s"} parsed`;
  served.stop();

  // Nothing is fetched but the page's own files, and nothing is left in the
  // browser. Read after every state has been opened, so the set covers the
  // whole run rather than one page load.
  const origins = new Set([new URL(base).origin, new URL(served.url).origin]);
  const own = new Set(["/", "/index.html", "/tokens.css", "/app.css", "/app.js", "/wasm_exec.js", "/cloudarq.wasm"]);
  const elsewhere = [...requested].filter(url => {
    const at = new URL(url);
    return !origins.has(at.origin) || !own.has(at.pathname);
  });
  requests = requested.size;
  check("the page fetches nothing but the files it is made of", elsewhere.length === 0, elsewhere.join(", "));
  check("the page did fetch its own files", requested.size >= own.size, `${requested.size} requests over the whole run`);
  const left = await evaluate(`(async () => {
    const out = { cookie: document.cookie, local: null, session: null, databases: null, caches: null };
    try { out.local = localStorage.length; } catch (err) { out.local = err.name; }
    try { out.session = sessionStorage.length; } catch (err) { out.session = err.name; }
    try { out.databases = (await indexedDB.databases()).map(d => d.name); } catch (err) { out.databases = err.name; }
    try { out.caches = await caches.keys(); } catch (err) { out.caches = err.name; }
    return out;
  })()`);
  check("the page leaves nothing in the browser", left.cookie === "" && left.local === 0 && left.session === 0 && (left.databases || []).length === 0 && (left.caches || []).length === 0, JSON.stringify(left));
} finally {
  ws.close();
  chrome.kill("SIGKILL");
  stopEmulator();
  server.close();
  await sleep(100);
  rmSync(profile, { recursive: true, force: true });
}

if (errors.length) {
  console.error(`page check: the page raised ${errors.length} error(s) in Chrome:\n  ${errors.join("\n  ")}`);
  process.exit(1);
}
for (const f of failures) console.error(`FAIL: ${f}`);
const undecided = [...incompleteSeen].map(([id, n]) => `${id}\u00d7${n}`).join(", ") || "none";
console.log(`page check: ${checks} assertions read in Chrome, ${failures.length} wrong`);
console.log(`axe: axe-core ${axeVersion} run over ${audits} states, ${violations} violations; left undecided and read by the contrast check below: ${undecided}`);
console.log(`contrast: ${contrastPairs} pairs read out of Chrome in both themes, each equal to the ratio written beside its token in web/tokens.css and at least ${textFloor}:1`);
console.log(`hierarchy: ${sentencesRead} finding sentences read across those states, ${listingsRead} listings read line by line for the ink they carry`);
console.log(`network: ${requests} requests over the whole run, all of them the page's own files; no cookie, no storage, no database, no cache`);
console.log(`headers: ${headersRead} required headers read out of web/dist/_headers and again out of the response the pages emulator built from it (${emulatorUsed}), with the page loaded and evaluated under them`);
if (checks === 0 || audits === 0 || contrastPairs === 0 || sentencesRead === 0 || listingsRead === 0 || headersRead === 0 || failures.length > 0) process.exit(1);
