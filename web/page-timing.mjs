// The page's re-evaluation, timed where it happens: in Chrome, on a
// keystroke, on a 50-statement policy, as the median of a hundred real ones
// on an idle machine. The engine alone is timed by web/diff.mjs in node;
// this serves the built page to a private headless Chrome, pastes the
// policy, and then types a hundred characters into the document with the
// answer on screen.
//
// Two numbers come out of each keystroke and both are printed: the page's
// own work, and the whole wait from the key to the answer laid out. They
// differ by the one item no page decides — the interval until the display's
// next frame — and the budgets below say which is held to what and why.
//
// The character is typed, not assigned. A harness that writes the whole
// textarea value — setRangeText, or value = — makes Chrome re-shape all 855
// lines of the document synchronously before the input event fires, which
// is work no keystroke does; measured against this build that method reads
// about 5 ms per edit higher than a key. So the edit here is a real key
// event through the debugger, the same path a reader's keyboard takes, and
// the window measured runs from the page's own keydown listener to the end
// of a forced style and layout after the frame that renders the answer.
//
// The page answers a keystroke inside the keystroke, so its re-evaluation
// lands before the listener this harness adds — which is registered after
// the page's and therefore hears the input event after it. That is why the
// breakdown below charges the engine's call and the page's rendering to
// "the browser's editing and the page's answer" rather than to the frame.
//
// The machine's background load is sampled before Chrome starts and again
// after it is gone, from two angles, because either one hides the other. The
// total across all cores catches a machine that is busy everywhere. The
// busiest single process catches the one that is busy where it matters: a
// terminal renderer holding 44% of one core reads as 5% of an eight-core
// total, and the first baseline this harness produced was taken beside
// exactly that and came out twice as slow as the same build measured later.
// Past either ceiling nothing is printed but the refusal: a number printed
// beside the word "not recorded" is a number that gets quoted anyway.
//
//   node web/page-timing.mjs <dist dir> <fifty-statements.json>
//
// Exits non-zero when either median exceeds its budget, when the machine was
// not idle, or when no Chrome can be found: a measurement that did not run
// is not a pass. Set CHROME to the browser's path when it is not at one
// of the usual ones.
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { cpus, totalmem } from "node:os";
import { resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

import { findChrome, HEADLESS_FLAGS, launch, serveDirectory } from "./chrome.mjs";

const [dist, fiftyPath] = process.argv.slice(2);
if (!dist || !fiftyPath) {
  console.error("usage: node web/page-timing.mjs <dist dir> <fifty-statements.json>");
  process.exit(2);
}
// Two figures, both printed, either one over its budget failing the run.
//
// The 16 ms is the page's own work: from the page's keydown handler to the
// end of the style and layout forced after the frame that re-renders the
// answer, which is the re-evaluation product/LAUNCH-STANDARD.md §1 names and
// everything about the keystroke the page decides. The 33 ms is the whole
// latency a reader feels, key to the answer laid out, and it contains one
// thing no page controls: the wait for the display's next frame, which on a
// 60 Hz screen is up to 16.7 ms and is measured and printed below. Two
// frames is what that allows for.
//
// The Architect's decision of record, 2026-09-20 07:14, delegated by
// Abdallah; product/LAUNCH-STANDARD.md §1 carries the row's older wording,
// which reads as the second figure held to the first figure's budget, and
// the number that reading produces is printed here on every run so that
// nothing hides in the definition.
const budgetMs = 16;
const paintBudgetMs = 33;
const edits = 100;
const idleCeilingPercent = 20;      // the total, every core normalised into 100%
const busiestCeilingPercent = 25;   // one process, where 100% is one whole core

// The background CPU, all cores normalised to 100%, over two seconds.
// On macOS `top -l 2` prints two CPU lines and the first is the average
// since boot, which reads high on a machine that has been busy at any point;
// the second is the interval just sampled. Where neither method works the
// figure is not measured, and a timing without it is not recorded.
async function cpuBusyPercent() {
  if (process.platform === "darwin") {
    const out = spawnSync("top", ["-l", "2", "-s", "2", "-n", "0"], { encoding: "utf8" }).stdout || "";
    const lines = out.split("\n").filter(l => l.startsWith("CPU usage:"));
    const idle = lines.length >= 2 ? Number(lines[1].match(/([\d.]+)% idle/)?.[1]) : NaN;
    return Number.isFinite(idle) ? 100 - idle : null;
  }
  if (process.platform === "linux") {
    const jiffies = () => {
      const [, ...fields] = readFileSync("/proc/stat", "utf8").split("\n")[0].trim().split(/\s+/);
      const all = fields.map(Number);
      return { idle: all[3] + all[4], total: all.reduce((a, b) => a + b, 0) };
    };
    const first = jiffies();
    await sleep(2000);
    const second = jiffies();
    const total = second.total - first.total;
    return total > 0 ? 100 * (1 - (second.idle - first.idle) / total) : null;
  }
  return null;
}

// The busiest process on the machine, this one excluded. ps reports %cpu
// per core — 100% is one core saturated — and on macOS it is a decaying
// average over the last minute, so a process that was busy during the run
// is still visible in the sample taken after it.
function busiestProcess() {
  const out = spawnSync("ps", ["-Ao", "pid=,pcpu=,comm="], { encoding: "utf8" }).stdout || "";
  let worst = null;
  for (const line of out.split("\n")) {
    const fields = line.trim().match(/^(\d+)\s+([\d.]+)\s+(\S.*)$/);
    if (!fields) continue;
    const [, pid, percent, command] = fields;
    if (Number(pid) === process.pid) continue;
    if (!worst || Number(percent) > worst.percent) worst = { percent: Number(percent), name: command.split("/").pop() };
  }
  return worst;
}

const background = async () => ({ total: await cpuBusyPercent(), busiest: busiestProcess() });
const loaded = s => s.total === null || s.total > idleCeilingPercent || s.busiest === null || s.busiest.percent > busiestCeilingPercent;
const describe = s =>
  `${s.total === null ? "total not read" : s.total.toFixed(1) + "% busy across " + cpus().length + " cores"}, ` +
  `busiest process ${s.busiest === null ? "not read" : `${s.busiest.name} at ${s.busiest.percent.toFixed(1)}% of a core`}`;

// Elements are addressed as [id$=name] rather than #name: the component
// spells every id under the instance that rendered it, so that two explorers
// on one page do not name the same element twice. The suffix is the part that
// does not depend on which instance rendered it.
const chromePath = findChrome();
if (!chromePath) {
  console.error("page timing: not measured, no Chrome found; set CHROME to the browser's path");
  process.exit(1);
}

// The machine is often busy for a moment before the run — the step of the
// build that just finished, a browser closing behind it. The figure is
// sampled again until it is under the ceiling or the wait runs out, and
// what was waited for is printed beside it. The ceiling does not move: a
// machine that never falls under it is a machine this is not measured on.
const settleSeconds = 60;
let before = await background();
const startedWaiting = Date.now();
while (loaded(before) && Date.now() - startedWaiting < settleSeconds * 1000) before = await background();
const waitedSeconds = Math.round((Date.now() - startedWaiting) / 1000);
if (loaded(before)) {
  console.error(`page timing: not measured, after ${waitedSeconds} s of waiting the machine was ${describe(before)}, past the ${idleCeilingPercent}% total / ${busiestCeilingPercent}% single-process ceiling`);
  process.exit(1);
}

// the built page, served from the dist directory over loopback; the policy
// under test is served beside it so the page can fetch it
const server = await serveDirectory(dist, { alias: { "/fifty.json": resolve(fiftyPath) } });
const url = server.base;

// Runtime.enable only: attaching the debugger (Debugger.enable) keeps V8's
// wasm on its baseline tier, which measured at 14 ms where the optimised
// tier measures at 5 ms; a debugger is not what a reader's tab has.
const flags = HEADLESS_FLAGS;
const browser = await launch(chromePath, { label: "cloudarq-page-timing", flags });
const { errors, send, evaluate } = browser;
browser.on(msg => {
  if (msg.method === "Log.entryAdded" && msg.params.entry.level === "error") errors.push(msg.params.entry.text);
});

// three positions in the document, cycled: an edit in the first statement
// moves every later byte offset, one in the last moves none
const anchors = ['"Sid": "Repository0', '"Sid": "Repository24', '"Sid": "Repository49'];

// the answer on screen for the 50-statement policy, with the document open
// in the box for editing
const setUp = `(async () => {
  const fifty = await (await fetch("fifty.json")).text();
  const box = document.querySelector("textarea[name=policy]");
  box.focus();
  const t0 = performance.now();
  box.value = fifty;
  box.dispatchEvent(new InputEvent("input", { inputType: "insertFromPaste", bubbles: true }));
  await new Promise(r => requestAnimationFrame(r));
  void document.body.offsetHeight;
  const paste = performance.now() - t0;
  await new Promise(r => setTimeout(r, 200));
  document.querySelector("[id$=policy-edit]").click();
  await new Promise(r => setTimeout(r, 200));

  const editor = document.querySelector("textarea[name=policy]");
  window.__edits = [];
  // The keystroke's own clock starts where the browser's does, before the
  // character is inserted; this listener is on the way down, ahead of the
  // page's own. The frame callback registered here runs first in the frame
  // the edit lands in, because it is registered before the page registers
  // its own, and marks where the wait for the frame ended.
  // What the browser itself says the keystroke cost: an event-timing entry's
  // duration runs from the key to the paint that follows its handling, which
  // is the interaction-to-next-paint the launch standard's §1 row names. It
  // is reported in 8 ms steps and only for events of 16 ms or more, so the
  // count of entries is half the number: a keystroke that does not appear
  // took under 16 ms to paint.
  window.__paints = [];
  new PerformanceObserver(list => {
    for (const entry of list.getEntries()) if (entry.name === "keydown") window.__paints.push(entry.duration);
  }).observe({ type: "event", durationThreshold: 16 });

  let pressed = 0;
  let frameBegan = 0;
  let typed = 0;
  document.addEventListener("keydown", () => {
    pressed = performance.now();
    requestAnimationFrame(() => { frameBegan = performance.now(); });
  }, true);
  // Registered on the document, in the bubble phase, and after the page has
  // registered its own, so it is heard after the page's answer either way the
  // page listens: a handler on the box itself runs in the target phase, ahead
  // of this one, and a framework that delegates its events registers on this
  // same root before this line runs. A listener on the box would be heard
  // before a delegated handler, and everything the page did would land in
  // "waiting for the frame" instead of in the page's own work — which is the
  // under-count this measurement exists to prevent.
  document.addEventListener("input", () => {
    typed = performance.now();
    requestAnimationFrame(() => {
      const callback = performance.now() - pressed;
      const rendered = performance.now();
      void document.body.offsetHeight;
      window.__edits.push({
        callback,
        withLayout: performance.now() - pressed,
        // where the time between the key and the answer went
        editing: typed - pressed,
        waiting: frameBegan - typed,
        frame: rendered - frameBegan,
        forcedLayout: performance.now() - rendered,
      });
    });
  });
  // the display's own cadence, which is the floor under the wait between a
  // key and the frame that answers it
  const intervals = [];
  await new Promise(done => {
    let previous = 0;
    let n = 0;
    const tick = now => {
      if (previous) intervals.push(now - previous);
      previous = now;
      if (++n < 60) requestAnimationFrame(tick); else done();
    };
    requestAnimationFrame(tick);
  });
  intervals.sort((a, b) => a - b);

  const anchors = ${JSON.stringify(anchors)};
  window.__caret = i => {
    const at = editor.value.indexOf(anchors[i]) + anchors[i].length;
    editor.focus();
    editor.setSelectionRange(at, at);
    return at;
  };
  return { chrome: navigator.userAgent.match(/Chrome\\/[\\d.]+/)[0], grants: document.querySelectorAll("article.answer").length, readout: document.querySelector("[id$=answer-readout]").textContent, policyReadout: document.querySelector("[id$=policy-readout]").textContent, paste, frameInterval: intervals[intervals.length >> 1], lines: editor.value.split("\\n").length, bytes: editor.value.length };
})()`;

const key = type => ({ type, key: "x", code: "KeyX", windowsVirtualKeyCode: 88, nativeVirtualKeyCode: 88, ...(type === "keyDown" ? { text: "x", unmodifiedText: "x" } : {}) });

const median = xs => { const s = [...xs].sort((a, b) => a - b); return s[Math.floor(s.length / 2)]; };
const quantile = (xs, q) => { const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(s.length * q))]; };
const ms = x => `${x.toFixed(1)} ms`;
let setup;
let after;
try {
  await send("Page.enable");
  await send("Runtime.enable");
  await send("Log.enable");
  await send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
  await send("Page.navigate", { url });
  // What says the engine has arrived is the page, not a global: the loader
  // returns an engine object and writes nothing to globalThis.
  for (let i = 0; i < 100 && !(await evaluate("(document.querySelector('[id$=policy-readout]') || {}).textContent !== 'loading the engine' && (document.querySelector('[id$=answer-body]') || {}).childElementCount > 0")); i++) await sleep(100);
  await sleep(200);
  // the page opens on a document of its own; the box is emptied first so
  // that the policy under test is what is measured
  await evaluate("document.querySelector('[id$=policy-clear]').click()");
  await sleep(200);
  setup = await evaluate(setUp);
  for (let i = 0; i < edits; i++) {
    await evaluate(`window.__caret(${i % 3})`);
    await send("Input.dispatchKeyEvent", key("keyDown"));
    await send("Input.dispatchKeyEvent", key("keyUp"));
    for (let w = 0; w < 100 && (await evaluate("window.__edits.length")) <= i; w++) await sleep(5);
    await sleep(40);
  }
  setup.edits = await evaluate("window.__edits");
  setup.paints = await evaluate("window.__paints");
  setup.finalReadout = await evaluate("document.querySelector('[id$=policy-readout]').textContent");
} finally {
  server.stop();
  await browser.stop();
}
// after the browser is gone, so that the run's own Chrome is not read as the
// machine's load, and while ps still carries the last minute of anything that
// ran beside it
after = await background();

if (errors.length) {
  console.error(`page timing: the page raised ${errors.length} error(s) in Chrome:\n  ${errors.join("\n  ")}`);
  process.exit(1);
}
if (setup.grants !== 50 || setup.readout !== "50 grants · exact") {
  console.error(`page timing: the page showed ${setup.grants} grants and read "${setup.readout}" for the 50-statement policy`);
  process.exit(1);
}
if (setup.edits.length !== edits) {
  console.error(`page timing: ${setup.edits.length} of ${edits} keystrokes were answered; the rest were not measured`);
  process.exit(1);
}
// Every keystroke inserts one byte into the document, and the policy readout
// prints the document's size as the engine read it. So the size at the end
// must be the size at the start plus one per keystroke: a page that answered
// fewer keystrokes than it was given would be measured on work it did not do.
// This is read off the page rather than off a wrapper around the engine,
// because the loader writes no global and there is nothing to wrap.
const bytesIn = text => Number(/· (\d+) bytes/.exec(text)?.[1] ?? NaN);
const bytesBefore = bytesIn(setup.policyReadout);
const bytesAfter = bytesIn(setup.finalReadout);
if (!(bytesAfter - bytesBefore === edits)) {
  console.error(`page timing: the document went from ${bytesBefore} to ${bytesAfter} bytes over ${edits} keystrokes; one re-evaluation per keystroke is what is being timed ("${setup.policyReadout}" -> "${setup.finalReadout}")`);
  process.exit(1);
}

// The guard comes before the numbers, not after them: a measurement taken on
// a machine that was busy is not a measurement, and printing it under the
// word "not recorded" only means it gets quoted with the word dropped.
if (loaded(after)) {
  console.error(`page timing: not recorded, after the run the machine was ${describe(after)}, past the ${idleCeilingPercent}% total / ${busiestCeilingPercent}% single-process ceiling; it was ${describe(before)} before it`);
  process.exit(1);
}

const withLayout = setup.edits.map(e => e.withLayout);
const callback = setup.edits.map(e => e.callback);
// everything the page is charged for, the wait for the frame aside: the
// browser's editing and the page's answer inside the keystroke, whatever
// the frame itself then does, and the style and layout forced after it
const work = setup.edits.map(e => e.editing + e.frame + e.forcedLayout);
const machine = `${cpus()[0].model}, ${cpus().length} cores, ${Math.round(totalmem() / 1073741824)} GB`;
console.log(`page timing in ${setup.chrome} on ${machine}:`);
console.log(`  headless, ${flags.join(" ")}; ${setup.lines} lines and ${setup.bytes} bytes in the box, ${setup.grants} grants on screen`);
console.log(`  background load before Chrome started${waitedSeconds > 4 ? `, after ${waitedSeconds} s of waiting for the machine to settle` : ""}: ${describe(before)}`);
console.log(`  background load after Chrome was gone: ${describe(after)}; ceilings ${idleCeilingPercent}% total, ${busiestCeilingPercent}% for one process`);
console.log(`  the display's cadence here: a frame every ${ms(setup.frameInterval)}, which is the floor under the wait below`);
console.log(`  paste, first render of the answer: ${ms(setup.paste)} with style and layout`);
console.log(`  a typed character, answer re-evaluated, over ${edits} keystrokes:`);
console.log(`    with style and layout: median ${ms(median(withLayout))}, first 8 median ${ms(median(withLayout.slice(0, 8)))}, p90 ${ms(quantile(withLayout, 0.9))}, max ${ms(Math.max(...withLayout))}`);
console.log(`    to the end of the frame callback: median ${ms(median(callback))}`);
console.log(`    where it goes: ${ms(median(setup.edits.map(e => e.editing)))} the browser's editing and the page's answer, ${ms(median(setup.edits.map(e => e.waiting)))} waiting for the frame, ${ms(median(setup.edits.map(e => e.frame)))} in the frame itself, ${ms(median(setup.edits.map(e => e.forcedLayout)))} the style and layout forced after it`);
console.log(`    the engine's own call is not carved out here: it is timed in node by web/diff.mjs, and the page's share of the frame is the first figure on the line above`);
console.log(`    the page's own work, the wait for the frame excluded: median ${ms(median(work))}, first 8 median ${ms(median(work.slice(0, 8)))}, p90 ${ms(quantile(work, 0.9))}, max ${ms(Math.max(...work))}`);
console.log(`    from the key to the paint that answers it, as the browser reports it: ${setup.paints.length} of ${edits} keystrokes reached the 16 ms the event-timing API reports at all${setup.paints.length ? `, median ${ms(median(setup.paints))}` : ""}`);
console.log(`    every edit, with layout: ${withLayout.map(x => x.toFixed(1)).join(", ")}`);
console.log(`    every edit, the page's own work: ${work.map(x => x.toFixed(1)).join(", ")}`);
console.log(`  the caret cycles three positions, ${anchors.join(", ")}: an edit in the first statement moves every later byte offset, one in the last moves none`);
console.log(`  the numbers exclude paint, pre-paint and compositing, which follow the forced layout, and the GPU, which these flags disable`);
const over = [];
if (median(work) > budgetMs) over.push(`the page's own work is ${ms(median(work))}, past ${budgetMs} ms`);
if (median(withLayout) > paintBudgetMs) over.push(`key to the answer laid out is ${ms(median(withLayout))}, past ${paintBudgetMs} ms`);
if (over.length) {
  console.error(`FAIL: over ${edits} keystrokes, ${over.join(", and ")}`);
  process.exit(1);
}
console.log(`  budget: the page's own work ${ms(median(work))} is within ${budgetMs} ms, and key to the answer laid out ${ms(median(withLayout))} is within ${paintBudgetMs} ms, of which ${ms(median(setup.edits.map(e => e.waiting)))} is the wait for the display's next frame at a cadence of ${ms(setup.frameInterval)}`);
console.log(`  read the other way, as one number from the key to the answer laid out against the 16 ms: ${ms(median(withLayout))}, which is ${median(withLayout) <= budgetMs ? "within" : "past"} it`);
