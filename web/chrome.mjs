// A private Chrome, and a directory served to it over loopback.
//
// Three harnesses drive a browser here — web/page-check.mjs reads the page's
// behaviour, web/page-timing.mjs measures the keystroke, web/consumer-check.mjs
// reads what a host that installs the package gets — and they were three
// copies of the same forty lines: find the browser, start it on a profile of
// its own, open the debugger socket, evaluate an expression, serve the built
// files. The copies had already drifted in the parts that matter least and
// agreed in the parts that matter most, which is the wrong way round.
//
// No CDP domain is enabled here. page-timing attaches nothing but
// Runtime.enable on purpose — Debugger.enable keeps V8's wasm on its baseline
// tier, which is not what a reader's tab runs — so what is listened to is the
// caller's decision, not this module's.
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { extname, join, resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

/** findChrome answers with the browser's path, or null. CHROME names it when
 *  it is not at one of the usual ones; the caller says what it was for, so
 *  the sentence a build prints is the sentence that run needed. */
export function findChrome() {
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

// extensions are off: one installed for every profile of the machine's Chrome
// injected a content script whose own exception was read as the page's
export const HEADLESS_FLAGS = [
	"--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-extensions", "--disable-gpu", "--hide-scrollbars",
];

/** launch starts Chrome on a profile of its own and opens the debugger
 *  socket. `on` registers a listener for every CDP event, `errors` collects
 *  what the page threw, and `stop` closes all of it, the profile included. */
export async function launch(chromePath, { label = "cloudarq", flags = HEADLESS_FLAGS, windowSize = "1440,900" } = {}) {
	const profile = mkdtempSync(join(tmpdir(), `${label}-`));
	// Chrome picks the port and writes it into the profile it was given. A
	// port this process picked would be a port another browser on the machine
	// may already hold, and attaching to somebody else's browser is not a
	// failure that announces itself: the run drives a page that is not the one
	// under test, or waits on one that never changes. It takes only a few
	// headless browsers left over from earlier runs, and this machine had six.
	const chrome = spawn(chromePath, [...flags, "--remote-debugging-port=0", `--user-data-dir=${profile}`, `--window-size=${windowSize}`, "about:blank"], { stdio: "ignore" });

	let port = null;
	for (let i = 0; i < 100 && port === null; i++) {
		try {
			const first = readFileSync(join(profile, "DevToolsActivePort"), "utf8").split("\n")[0];
			if (/^[0-9]+$/.test(first)) port = Number(first);
		} catch {}
		if (port === null) await sleep(100);
	}
	let socketUrl = null;
	for (let i = 0; i < 100 && port !== null && !socketUrl; i++) {
		try {
			const list = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
			socketUrl = list.find((t) => t.type === "page")?.webSocketDebuggerUrl ?? null;
		} catch {}
		if (!socketUrl) await sleep(100);
	}
	if (!socketUrl) {
		chrome.kill("SIGKILL");
		rmSync(profile, { recursive: true, force: true });
		throw new Error(port === null ? `chrome did not write a debugger port into ${profile}` : "chrome did not come up");
	}

	const ws = new WebSocket(socketUrl);
	await new Promise((open) => (ws.onopen = open));
	let seq = 0;
	const pending = new Map();
	const errors = [];
	const listeners = [];
	ws.onmessage = (m) => {
		const msg = JSON.parse(m.data);
		if (msg.id && pending.has(msg.id)) {
			pending.get(msg.id)(msg);
			pending.delete(msg.id);
		}
		if (msg.method === "Runtime.exceptionThrown") errors.push(msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text);
		for (const listener of listeners) listener(msg);
	};

	const send = (method, params = {}) => new Promise((resolve) => {
		const id = ++seq;
		pending.set(id, resolve);
		ws.send(JSON.stringify({ id, method, params }));
	});
	const evaluate = async (expression) => {
		const r = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
		if (r.result?.exceptionDetails) throw new Error(r.result.exceptionDetails.exception?.description || r.result.exceptionDetails.text);
		return r.result?.result?.value;
	};

	return {
		flags,
		errors,
		send,
		evaluate,
		on: (listener) => listeners.push(listener),
		stop: async () => {
			ws.close();
			chrome.kill("SIGKILL");
			await sleep(100);
			rmSync(profile, { recursive: true, force: true });
		},
	};
}

/** settleOn navigates to a URL and waits for the document at that URL to
 *  answer `predicate`. It throws rather than returning when the wait runs
 *  out.
 *
 *  Both halves are the point. Runtime.evaluate with no execution context id
 *  lands in whatever Chrome's default context is at that instant, and for a
 *  window after Page.navigate that is still the document being navigated
 *  away from — fully rendered, and answering any predicate the harness asks
 *  about the page it was just reading. So the query the navigation carries is
 *  part of what settles: every caller opens a state at a query of its own,
 *  and a predicate that has not reached that query has not reached that
 *  document. And a wait that ran out and read anyway is a measurement of
 *  whatever happened to be on screen, which is worse than no measurement:
 *  the harness that did it turned twelve of its own states into differences
 *  on one run and moved which gate caught a mutation.
 */
export async function settleOn(browser, url, predicate, { tries = 150, every = 100 } = {}) {
	const { search } = new URL(url);
	await browser.send("Page.navigate", { url });
	const settled = `location.search === ${JSON.stringify(search)} && (${predicate})`;
	for (let i = 0; i < tries; i++) {
		if (await browser.evaluate(settled)) return;
		await sleep(every);
	}
	throw new Error(`${url} did not settle within ${(tries * every) / 1000}s; still false: ${settled}`);
}

const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".wasm": "application/wasm", ".json": "application/json", ".woff2": "font/woff2" };

/** serveDirectory serves a directory of built files over loopback. `alias`
 *  maps a request path to a file outside the directory — the policy a timing
 *  run pastes lives beside the page rather than in it — and `hide` answers
 *  404 for a file the run is withholding on purpose, which is how a page is
 *  read when its engine does not arrive. */
export async function serveDirectory(dir, { alias = {}, hide = () => false } = {}) {
	const root = resolve(dir);
	const server = createServer((req, res) => {
		const asked = req.url === "/" ? "/index.html" : req.url.split("?")[0];
		const aliased = alias[asked] ? resolve(alias[asked]) : null;
		const path = aliased ?? join(root, asked);
		if ((!aliased && !path.startsWith(root)) || !existsSync(path) || statSync(path).isDirectory() || hide(path)) {
			res.writeHead(404).end();
			return;
		}
		res.writeHead(200, { "content-type": TYPES[extname(path)] || "application/octet-stream" }).end(readFileSync(path));
	});
	await new Promise((ready) => server.listen(0, "127.0.0.1", ready));
	const origin = `http://127.0.0.1:${server.address().port}`;
	return { origin, base: `${origin}/index.html`, stop: () => server.close() };
}
