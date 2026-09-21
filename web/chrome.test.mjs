// settleOn, against a server that answers awkwardly on purpose.
//
// The harnesses that drive Chrome open one state after another in the same
// tab, and every one of them waited by evaluating a predicate with no
// execution context id and then reading whatever was there. Two things go
// wrong that way, and both are here as a server response rather than as an
// argument:
//
//   a navigation that never arrives — 204 is the plainest of the responses a
//   browser cannot make a document out of — leaves the previous document up,
//   and it answers every predicate a harness could ask about the page it was
//   already reading. The state is then recorded off the page before it,
//   under the new state's name.
//
//   a wait that runs out and reads anyway measures whatever happened to be on
//   screen. That is worse than no measurement: it is a number with a name.
//
// Chrome is needed, so this runs from web/build.sh and not in CI.
//
//   node --test web/chrome.test.mjs
import { strictEqual } from "node:assert/strict";
import { createServer } from "node:http";
import { after, before, test } from "node:test";

import { findChrome, launch, settleOn } from "./chrome.mjs";

const chromePath = findChrome();
if (!chromePath) {
  console.error("chrome test: not run, no Chrome found; set CHROME to the browser's path");
  process.exit(1);
}

// One page under different queries: a mark written a tick after the document
// arrives, so that "the document is here" and "the document has rendered" are
// two different moments. `hold` delays the response, `nocontent` answers 204.
const server = createServer((req, res) => {
  const query = new URL(req.url, "http://127.0.0.1").searchParams;
  if (query.get("nocontent")) {
    res.writeHead(204).end();
    return;
  }
  const mark = query.get("mark") ?? "";
  const body = `<!doctype html>
<html lang=en><title>${mark}</title><body>
<script type="module">
  await new Promise(r => setTimeout(r, 150));
  const p = document.createElement("p");
  p.id = "mark";
  p.textContent = ${JSON.stringify(mark)};
  document.body.append(p);
</script>
</body></html>
`;
  setTimeout(() => res.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end(body), Number(query.get("hold") ?? 0));
});
await new Promise((ready) => server.listen(0, "127.0.0.1", ready));
// A listening server keeps node's event loop alive, and so does a keep-alive
// connection a browser left open on it. Neither is this process's reason to
// exist: the tests are, and a run that finished its tests and then hung was
// what said so.
server.unref();
const base = `http://127.0.0.1:${server.address().port}/`;

let browser;
before(async () => {
  browser = await launch(chromePath, { label: "cloudarq-chrome-test" });
  await browser.send("Page.enable");
  await browser.send("Runtime.enable");
});
after(async () => {
  await browser.stop();
  server.closeAllConnections();
  server.close();
});

const rendered = "document.getElementById('mark') !== null";
const failed = async (url, options) => {
  try {
    await settleOn(browser, url, rendered, options);
  } catch (err) {
    return err.message;
  }
  return "";
};

test("a state whose navigation never arrived is not read off the page before it", async () => {
  await settleOn(browser, `${base}?1&mark=first`, rendered);
  strictEqual(await browser.evaluate("document.getElementById('mark').textContent"), "first");

  const why = await failed(`${base}?2&mark=second&nocontent=1`, { tries: 3, every: 50 });
  strictEqual(why.includes("did not settle"), true, "the wait returned on a navigation that never arrived");
  strictEqual(await browser.evaluate("document.getElementById('mark').textContent"), "first", "the browser did not stay where it was, so this proves nothing");
});

test("a state whose document is slow is waited for and read on that document", async () => {
  await settleOn(browser, `${base}?3&mark=third&hold=400`, rendered);
  strictEqual(await browser.evaluate("document.getElementById('mark').textContent"), "third");
  strictEqual(await browser.evaluate("location.search"), "?3&mark=third&hold=400");
});

test("a wait that runs out says so rather than reading what is on screen", async () => {
  const why = await failed(`${base}?4&mark=fourth`, { tries: 3, every: 50 });
  strictEqual(why.includes("did not settle within 0.15s"), true, `settleOn returned instead of throwing: ${why || "no error"}`);
  // it gave up where it navigated to: the failure is about the wait, not
  // about having landed somewhere else. The mark is not there yet — that is
  // the reason the wait ran out — so the address is what says so.
  strictEqual(await browser.evaluate("location.search"), "?4&mark=fourth");
});
