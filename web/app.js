// The explorer. The page is a function of the fragment, the engine is the
// answer package compiled to WebAssembly, and nothing here evaluates: every
// sentence, value and number on the page comes from admits() and explain()
// or from the static copy in index.html.
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

// ---- the engine: bytes in through the module's inbox, the answer out from
// where the module says it is; two functions on globalThis wrap that ----

export async function loadEngine(module, { memoryBound = 1 << 28 } = {}) {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  // A library module initialises and returns: wasm_exec's run() calls the
  // module's _initialize before its first await, so an instance is ready as
  // soon as run() has been called, and the promise only carries an exit
  // that never comes. The instance is kept warm across calls: a fresh one
  // grows its heap from nothing under the collector on every call, which
  // costs 3.6 s on the largest document the engine reads.
  function fresh() {
    const go = new Go();
    const instance = new WebAssembly.Instance(module, go.importObject);
    go.run(instance);
    return instance;
  }
  let instance = fresh();
  let replaced = 0;
  let peak = 0;
  // Linear memory never shrinks, and the collector doubles it rather than
  // compact when a large answer finds no contiguous room. Measured in node
  // on the shipped build, over 200 admits and 200 explain calls on a fresh
  // instance: the 50-statement policy stands at 18 MB after its admits on
  // every run and settles at 18 MB on twelve of sixteen instances and 36 MB
  // on four; the largest document the engine reads settles at 288 MB on two
  // runs of five and 576 on three, with no ceiling in the way. Where a run's doublings
  // land is not deterministic, so past the bound the instance is replaced,
  // at a cost of about 80 ms on the call after, on that document; the tab's
  // memory therefore has a ceiling of one doubling past the bound.
  // The bound is a parameter so that the replacement can be proven on a
  // small one, in web/diff.mjs.
  // A pointer the module returns is a wasm i32, which reads as negative
  // once memory has grown past 2 GB; memory.buffer is read after every call
  // into the module, because growth replaces the buffer.
  const call = (name, ...texts) => {
    const { memory, reserve, answerAt } = instance.exports;
    const parts = texts.map(t => encoder.encode(t));
    let text;
    try {
      const at = reserve(parts.reduce((n, p) => n + p.length, 0)) >>> 0;
      let offset = 0;
      for (const p of parts) {
        new Uint8Array(memory.buffer, at + offset, p.length).set(p);
        offset += p.length;
      }
      const length = instance.exports[name](...parts.map(p => p.length));
      text = decoder.decode(new Uint8Array(memory.buffer, answerAt() >>> 0, length));
    } catch (err) {
      // a trap leaves the instance dead, every later call throwing too;
      // the caller is told once and the next call meets a live engine
      instance = fresh();
      replaced++;
      throw err;
    }
    peak = Math.max(peak, memory.buffer.byteLength);
    if (memory.buffer.byteLength > memoryBound) {
      instance = fresh();
      replaced++;
    }
    return text;
  };
  globalThis.admits = policy => call("admits", policy);
  globalThis.explain = (policy, token) => call("explain", policy, token);
  return {
    memoryBytes: () => instance.exports.memory.buffer.byteLength,
    peakMemoryBytes: () => peak,
    replacements: () => replaced,
  };
}

// ---- the fragment ----

const VIEWS = ["admits", "token"];

function parseFragment(hash) {
  const parts = hash.replace(/^#/, "").split(".");
  if (parts[0] !== "v1") return { dialect: "aws", policy: "", token: "", view: "admits" };
  return { dialect: parts[1] || "aws", policy: parts[2] || "", token: parts[3] || "", view: VIEWS.includes(parts[4]) ? parts[4] : "admits" };
}

function buildFragment(encoded) {
  return "#" + ["v1", encoded.dialect, encoded.policy, encoded.token, encoded.view === "admits" ? "" : encoded.view].join(".").replace(/\.+$/, "");
}

const base64url = {
  encode(bytes) {
    let binary = "";
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
  decode(text) {
    return Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
  },
};

async function deflate(text) {
  if (!text) return "";
  const stream = new Blob([text]).stream().pipeThrough(new CompressionStream("deflate-raw"));
  return base64url.encode(new Uint8Array(await new Response(stream).arrayBuffer()));
}

async function inflate(encoded) {
  if (!encoded) return "";
  const stream = new Blob([base64url.decode(encoded)]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  return new Response(stream).text();
}

async function fragmentOf(state) {
  const [policy, token] = await Promise.all([deflate(state.policy), deflate(state.token)]);
  return buildFragment({ dialect: state.dialect, policy, token, view: state.view });
}

// ---- the page ----

function explorer() {
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  // el builds an element: attributes by name, children as text or nodes
  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [name, value] of Object.entries(attrs)) {
      if (value === false || value == null) continue;
      node.setAttribute(name, value === true ? "" : value);
    }
    node.append(...children.flat(Infinity).filter(c => c != null));
    return node;
  }
  const template = id => $(`#${id}`).content.firstElementChild.cloneNode(true);

  const state = { dialect: "aws", policy: "", token: "", view: "admits" };
  let answer = null; // admits() for the policy, or null when nothing is pasted
  let explanation = null; // explain() for the token, or null when there is none
  let editing = false; // the policy pane shows the textarea rather than the listing
  let unreadableLink = ""; // why the address's fragment could not be read, when it could not
  const selected = new Set(); // statement indices selected in both panes
  const examples = Object.fromEntries($$("script[data-example]").map(s => [s.dataset.example, s.textContent]));
  // The page opens answering. The document it opens with is a conformance
  // case whose answer is the argument the page exists to make: a condition
  // that reads as a constraint and is not one.
  const openingDocument = "07-expressible-by-one-provider";
  // a document of the corpus is named wherever it is shown, so that a reader
  // knows the answer on screen is not about anything of theirs
  const exampleNamed = text => Object.keys(examples).find(name => examples[name] === text) || "";

  let evaluated = null; // the policy text the answer on the page is for
  let policyBytes = new Uint8Array(); // the same text as bytes, which the engine's offsets index
  function evaluate() {
    const changed = state.policy !== evaluated;
    evaluated = state.policy;
    policyBytes = encoder.encode(state.policy);
    answer = state.policy.trim() ? answerOf(() => admits(state.policy)) : null;
    const readable = answer && !answer.error;
    if (changed) {
      // a selection belongs to one document; a document of one statement
      // opens with it selected, so the tint and the rule that join the
      // panes are on screen before anything is pressed
      selected.clear();
      if (readable && answer.document.statements.length === 1) selected.add(0);
    }
    explanation = readable && state.view === "token" && state.token.trim() ? answerOf(() => explain(state.policy, state.token)) : null;
  }

  // answerOf reads one answer from the engine. An engine that stops is
  // answered for, so that the previous answer never stays on screen for a
  // document it was not about.
  function answerOf(ask) {
    let text;
    try {
      text = ask();
    } catch (err) {
      return { v: 1, stopped: true, error: err.message, grants: [] };
    }
    const parsed = JSON.parse(text);
    if (parsed.v !== 1) return { v: parsed.v, error: `the engine answered with version ${parsed.v}; this page reads version 1`, grants: [] };
    return parsed;
  }

  function render() {
    renderPolicy();
    renderAnswer();
    for (const a of $$("a[data-view]")) {
      if (a.dataset.view === state.view) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
    }
    renderShare();
  }

  function refresh() {
    evaluate();
    render();
  }

  // ---- navigation: a link followed, or the address bar changed ----

  // encoded is the state as the fragment spells it, kept so that every link
  // on the page can be spelt from it by concatenation: the policy is
  // deflated once per change, not once per link
  let encoded = { dialect: "aws", policy: "", token: "" };
  const hrefOf = next => buildFragment({ ...encoded, ...next });

  let writes = 0;
  async function writeFragment(how) {
    const turn = ++writes;
    const next = { dialect: state.dialect, policy: await deflate(state.policy), token: await deflate(state.token) };
    if (turn !== writes) return; // a later write already holds the newer state
    encoded = next;
    history[how](null, "", location.pathname + location.search + buildFragment({ ...encoded, view: state.view }));
    refreshLinks();
    renderShare();
  }

  // Every link whose target is a view of the current policy gets the real
  // fragment for it, so that hovering, copying the address and opening in a
  // new tab all see that state. It is spelt from `encoded` and so is redone
  // when `encoded` changes and not on every render: on a fifty-grant answer
  // a keystroke would otherwise write fifty witness links twice, once with
  // the fragment of the document as it was a keystroke ago.
  function refreshLinks() {
    for (const a of $$("a[data-view]")) a.href = hrefOf({ view: a.dataset.view });
    for (const a of $$("a[data-token-encoded]")) a.href = hrefOf({ token: a.dataset.tokenEncoded, view: "token" });
  }
  for (const a of $$("a[data-view]")) a.onclick = e => { e.preventDefault(); go({ view: a.dataset.view }); };

  // tokenLink opens the token view on a token of the answer's own, a witness
  function tokenLink(text, token) {
    const a = el("a", { href: "#" }, text);
    a.onclick = e => { e.preventDefault(); go({ token, view: "token" }); };
    deflate(token).then(enc => { a.dataset.tokenEncoded = enc; a.href = hrefOf({ token: enc, view: "token" }); });
    return a;
  }

  // link gives an anchor the real fragment for a state of its own: an
  // example, or the empty state
  function link(a, next) {
    fragmentOf({ ...state, ...next }).then(hash => { a.href = hash; });
    a.onclick = e => {
      e.preventDefault();
      go(next);
    };
  }

  function go(next) {
    Object.assign(state, next);
    editing = false;
    unreadableLink = "";
    refresh();
    writeFragment("pushState");
  }

  // readFragment loads the state a link carries. A fragment that cannot be
  // read, which is what a link cut short when it was copied looks like,
  // loads nothing and says so; the page never shows an answer under an
  // address it did not come from.
  let reading = 0;
  async function readFragment() {
    const turn = ++reading;
    const hash = location.hash;
    if (!hash) {
      // the opening document writes its own address before it renders, so
      // that the view links, the witness links and the share row carry the
      // state a reader can copy, and the page is its own shared link
      const policy = examples[openingDocument];
      const next = { dialect: "aws", policy: await deflate(policy), token: "" };
      if (turn !== reading) return;
      Object.assign(state, { dialect: "aws", policy, token: "", view: "admits" });
      encoded = next;
      unreadableLink = "";
      editing = false;
      history.replaceState(null, "", location.pathname + location.search + buildFragment({ ...encoded, view: state.view }));
      refresh();
      refreshLinks();
      return;
    }
    let parsed = parseFragment(hash);
    let policy = "", token = "";
    unreadableLink = "";
    try {
      if (hash && !hash.startsWith("#v1.") && hash !== "#v1") throw new Error(`it begins with ${hash.slice(1).split(".")[0]}, and this page reads v1`);
      [policy, token] = await Promise.all([inflate(parsed.policy), inflate(parsed.token)]);
    } catch (err) {
      unreadableLink = err.message.includes("this page reads v1") ? err.message : "it is not the deflated text this page writes, which is what a link cut short when it was copied looks like";
      parsed = { dialect: "aws", policy: "", token: "", view: "admits" };
      policy = token = "";
    }
    if (turn !== reading) return;
    Object.assign(state, { dialect: parsed.dialect, policy, token, view: parsed.view });
    encoded = { dialect: parsed.dialect, policy: parsed.policy, token: parsed.token };
    editing = false;
    refresh();
    refreshLinks();
  }
  window.addEventListener("hashchange", readFragment);

  // A keystroke is answered where it is heard, not in the frame after it.
  // The browser's next frame is up to one display interval away — 16.7 ms on
  // a 60 Hz screen — and the re-evaluation fits inside that wait rather than
  // queueing behind it, so the answer lands in the frame the keystroke
  // arrived for instead of the one after. Measured on the 50-statement
  // policy, a hundred keystrokes each way: 20.4 ms from the key to the
  // answer laid out when the work waited for the frame, 13.6 ms when it does
  // not. A second keystroke before the browser has rendered would be a
  // second whole re-evaluation inside one frame, so that one waits for the
  // frame the first already asked for: the coalescing that used to be
  // unconditional, kept for the case that needs it.
  let rendering = false;
  let waiting = null;
  function oncePerFrame(fn) {
    if (rendering) { waiting = fn; return; }
    rendering = true;
    requestAnimationFrame(() => {
      rendering = false;
      const later = waiting;
      waiting = null;
      if (later) later();
    });
    fn();
  }

  // afterRender runs work the answer does not wait for, the address bar's
  // update, in a task after the frame has painted: deflating the document
  // and writing the address measured at 0.8 ms inside the frame, and a
  // reader looks at the answer, not the address
  let later = 0;
  function afterRender(fn) {
    clearTimeout(later);
    later = setTimeout(fn);
  }

  // ---- the policy pane ----

  const policyBody = $("#policy-body");
  const policyReadout = $("#policy-readout");
  const editToggle = $("#policy-edit");
  const clearLink = $("#policy-clear");

  let listed = null; // the policy text the listing on the page was built from
  function renderPolicy() {
    const listing = answer && !answer.error && !editing;
    const named = exampleNamed(state.policy);
    policyReadout.textContent = policyReadoutText();
    editToggle.textContent = listing ? "edit" : "listing";
    editToggle.hidden = !(answer && !answer.error);
    // over a corpus document the control that empties the pane is named for
    // what a reader wants from it; over a document of their own, clearing it
    // is all it does
    clearLink.textContent = named ? "paste your own" : "clear";
    clearLink.hidden = !state.policy;
    if (listing) {
      if (listed !== state.policy) {
        policyBody.replaceChildren(renderListing());
        listed = state.policy;
        for (const n of selected) selectStatement(n, true);
      }
      return;
    }
    listed = null;
    if (!$("textarea[name=policy]", policyBody)) {
      const paste = template("t-paste");
      const textarea = $("textarea", paste);
      textarea.value = state.policy;
      textarea.addEventListener("input", () => {
        const fresh = state.policy === "";
        state.policy = textarea.value;
        editing = true;
        unreadableLink = "";
        oncePerFrame(() => {
          evaluate();
          // a paste into an empty box lands as the listing, and the keyboard
          // lands with it, on the first statement's mark; typing stays in the box
          const landing = fresh && answer && !answer.error;
          if (landing) editing = false;
          render();
          if (landing) ($("button.mark[data-stmt]", policyBody) || editToggle).focus();
          afterRender(() => writeFragment("replaceState"));
        });
      });
      policyBody.replaceChildren(paste);
    }
    const textarea = $("textarea[name=policy]", policyBody);
    if (textarea.value !== state.policy) textarea.value = state.policy; // a link changed the state, not a keystroke
    $(".accepts", policyBody).hidden = Boolean(state.policy);
  }

  function policyReadoutText() {
    if (!state.policy.trim()) return "nothing pasted";
    if (answer.error) return `${state.dialect} · ${bytesOf(state.policy)} bytes · not read`;
    const n = answer.document.statements.length;
    // the case number is what the pane head has room for; the teaching block
    // under the answer spells the case out
    const named = exampleNamed(state.policy).split("-")[0];
    return `${state.dialect} trust policy · ${answer.document.bytes} bytes · ${n} ${n === 1 ? "statement" : "statements"}${named ? ` · example ${named}` : ""}`;
  }

  // the listing: every line of the pasted text, numbered, with a mark on the
  // first line of each statement and a rule beside the lines it spans
  function renderListing() {
    const lines = state.policy.split("\n");
    if (lines.at(-1) === "") lines.pop();
    const within = new Map(); // line number -> statement indices
    const starts = new Map(); // line number -> the statement that opens there
    for (const s of answer.document.statements) {
      for (let n = s.firstLine; n <= s.lastLine; n++) within.set(n, [...(within.get(n) || []), s.index]);
      if (!starts.has(s.firstLine)) starts.set(s.firstLine, s);
    }
    const listing = el("div", { class: "policy", role: "region", "aria-label": "the policy as pasted, with line numbers and statement marks" });
    lines.forEach((text, i) => {
      const n = i + 1;
      const opens = starts.get(n);
      const mark = opens
        ? el("button", { class: "mark", type: "button", "data-stmt": opens.index, "aria-pressed": "false", "aria-label": `statement ${opens.index}, ${opens.sid || "no Sid"}, lines ${opens.firstLine} to ${opens.lastLine}` }, `[${opens.index}]`)
        : el("span", { class: "mark" });
      listing.append(el("div", { id: `L${n}`, class: "l", "data-in": within.has(n) ? within.get(n).join(" ") : null }, mark, el("span", { class: "ln" }, String(n)), el("span", { class: "src" }, text)));
    });
    return listing;
  }

  editToggle.addEventListener("click", () => {
    editing = !editing;
    render();
  });
  // The control that empties the pane is a link to the empty state's own
  // address, #v1.aws, so that it can be copied, opened in another tab and
  // reloaded like every other state; only an address with no fragment at all
  // means the document the page opens with. Emptying the pane hides the
  // control — there is nothing left to clear — so the keyboard is moved into
  // the box the control exists to produce rather than dropped on an element
  // that is no longer there. The click handler `link` installs runs first
  // and has already rendered that box.
  link(clearLink, { policy: "", token: "", view: "admits" });
  clearLink.addEventListener("click", () => $("textarea[name=policy]", policyBody)?.focus());

  // a statement mark in the gutter and the statement's name in a grant head
  // are one control: pressing either selects the statement and its grants
  // in both panes and brings the counterpart into view
  function selectStatement(n, on) {
    if (on) selected.add(n); else selected.delete(n);
    for (const b of $$(`[data-stmt="${n}"]`)) b.setAttribute("aria-pressed", String(on));
    for (const line of $$(".l[data-in]")) {
      if (line.dataset.in.split(" ").includes(String(n))) line.toggleAttribute("data-selected", on);
    }
  }
  document.addEventListener("click", e => {
    const b = e.target.closest("[data-stmt]");
    if (!b) return;
    const on = b.getAttribute("aria-pressed") !== "true";
    selectStatement(b.dataset.stmt, on);
    if (!on) return;
    for (const other of $$(`[data-stmt="${b.dataset.stmt}"]`)) if (other !== b) other.scrollIntoView({ block: "nearest" });
  });

  // a reference marks one line or note and brings it into view; the mark is
  // not state and is not in the link
  document.addEventListener("click", e => {
    const b = e.target.closest("[data-ref]");
    if (!b) return;
    const target = document.getElementById(b.dataset.ref);
    if (!target) return;
    for (const m of $$("[data-mark]")) delete m.dataset.mark;
    target.dataset.mark = "";
    target.scrollIntoView({ block: "nearest" });
  });

  // ---- the answer pane ----

  const answerBody = $("#answer-body");
  const answerReadout = $("#answer-readout");

  function renderAnswer() {
    const readout = answerReadoutNodes();
    if (answerReadout.textContent !== readout.map(n => n.textContent ?? n).join("")) answerReadout.replaceChildren(...readout);
    if (state.view !== "admits" || !answer || answer.error) rendered.clear();
    if (state.view === "token") {
      renderTokenView();
      return;
    }
    if (!answer) {
      place(answerBody, [teaching()]);
      return;
    }
    if (answer.error) {
      const unreadable = template(answer.stopped ? "t-stopped" : "t-unreadable");
      $(".error", unreadable).textContent = answer.error;
      place(answerBody, [unreadable, teaching()]);
      return;
    }
    place(answerBody, [renderDocumentNotes(), ...renderGrants(), bridge(), teaching()].filter(Boolean));
    for (const n of selected) selectStatement(n, true);
  }

  // The way out of the page, under the last grant. The command is named for
  // what it will do and for what it does today: cmd/cloudarq prints a usage
  // line and exits, and a page that claimed otherwise would be the one
  // fabricated sentence on it.
  let bridgeLine = null;
  function bridge() {
    if (!bridgeLine) {
      bridgeLine = el("p", { class: "bridge prose" },
        "One policy, here. ", el("code", {}, "cloudarq admits"),
        " will run the same engine over every role in an account; today it prints a usage line. The engine is public: ",
        el("a", { href: "https://github.com/CloudArq-net/cloudarq" }, "github.com/CloudArq-net/cloudarq"));
    }
    return bridgeLine;
  }

  // What the page is, the corpus documents, and how to read an answer under
  // a closed disclosure. It is the foot of the answer pane in every state,
  // not a state of its own: the three documents are the way in, and the
  // disclosure is what the colours mean, which is owed to a reader looking
  // at their own policy for the first time as much as to an empty page.
  let teachBlock = null;
  function teaching() {
    if (!teachBlock) {
      teachBlock = template("t-teach");
      for (const a of $$("a[data-example]", teachBlock)) link(a, { policy: examples[a.dataset.example], token: "", view: "admits" });
    }
    showUnreadableLink(teachBlock);
    $("[data-copy=nothing]", teachBlock).hidden = Boolean(answer);
    return teachBlock;
  }

  // place makes the parent's children exactly these nodes, in this order,
  // touching only the positions that differ: a keystroke inside one
  // statement rebuilds one article, and the other forty-nine stay where
  // they are. Replacing every child with itself would make the browser
  // restyle and lay out the whole pane, which measured at 12 ms for fifty
  // grants, most of the budget.
  function place(parent, nodes) {
    const keep = new Set(nodes);
    nodes.forEach((node, i) => {
      const current = parent.children[i];
      if (current === node) return;
      if (current && !keep.has(current)) current.replaceWith(node);
      else parent.insertBefore(node, current ?? null);
    });
    while (parent.childElementCount > nodes.length) parent.lastElementChild.remove();
  }

  function showUnreadableLink(root) {
    const p = $("[data-copy=unreadable-link]", root);
    p.hidden = !unreadableLink;
    $(".reason", p).textContent = unreadableLink;
  }

  function answerReadoutNodes() {
    if (!answer || answer.error) return [];
    const grants = answer.grants;
    const caveats = grants.reduce((n, g) => n + g.notes.filter(note => note.kind === "caveat").length, 0);
    const head = `${grants.length} ${grants.length === 1 ? "grant" : "grants"} · `;
    if (grants.length === 0) return [`${head}nobody is named`];
    if (caveats === 0) return [head, el("span", { class: "v-exact" }, "exact")];
    const bounds = grants.filter(g => !g.exact).length;
    return [head, el("span", { class: "v-unknown" }, `${bounds === grants.length ? "" : bounds + " "}upper bound · ${caveats} ${caveats === 1 ? "caveat" : "caveats"}`)];
  }

  // the document's own anomalies, before any grant: a member the grammar
  // does not define, a Statement written twice
  let documentNotes = { key: null, node: null };
  function renderDocumentNotes() {
    const notes = answer.document.anomalies;
    if (notes.length === 0) return null;
    const key = JSON.stringify(notes);
    if (documentNotes.key !== key) {
      documentNotes = { key, node: el("div", { class: "answer" },
        el("h3", { class: "grant-head" }, el("span", {}, "document"), el("span", { class: "v-unknown" }, `${notes.length} ${notes.length === 1 ? "anomaly" : "anomalies"}`)),
        renderNotes("doc", notes, new Set())) };
    }
    return documentNotes.node;
  }

  // A keystroke changes one statement's grant and every later statement's
  // offset, so each grant's article is kept from the last answer while the
  // grant reads the same, and only its evidence, which quotes the document's
  // size, digest and byte offsets, is refreshed: its summary now, and its
  // body, which a closed details does not show, when the details is open or
  // is opened. The whole answer is rebuilt for a 50-statement policy in a
  // few frames; this is the difference between an instrument and a form.
  const rendered = new Map(); // grant number -> { grant, summarised, located, statement, article, details }
  function renderGrants() {
    const kept = new Map();
    const doc = answer.document;
    const located = JSON.stringify([doc.bytes, doc.lines, doc.sha256]);
    const articles = answer.grants.map(g => {
      const s = doc.statements[g.statement];
      const grant = JSON.stringify([g, s.firstLine, s.lastLine]);
      const summarised = JSON.stringify(s);
      let entry = rendered.get(g.number);
      if (!entry || entry.grant !== grant) {
        const article = renderGrant(g, s);
        entry = { grant, summarised: null, located: null, article, details: $("details.evidence", article) };
      }
      if (entry.summarised !== summarised) {
        entry.summarised = summarised;
        entry.statement = s;
        summariseEvidence(entry.details, s);
      }
      // a keystroke moves the document under every open evidence body; a
      // closed one is written by the toggle that opens it
      if (entry.located !== located) {
        entry.located = located;
        entry.bodyLocated = false;
        if (entry.details.open) locateEvidenceBody(entry);
      }
      kept.set(g.number, entry);
      return entry.article;
    });
    rendered.clear();
    for (const [number, entry] of kept) rendered.set(number, entry);
    return articles;
  }
  function locateEvidenceBody(entry) {
    locateEvidence(entry.details, entry.statement);
    entry.bodyLocated = true;
  }
  // toggle does not bubble, so it is heard on the way down
  answerBody.addEventListener("toggle", e => {
    if (!e.target.open || !e.target.matches("details.evidence")) return;
    for (const entry of rendered.values()) {
      if (entry.article.contains(e.target) && !entry.bodyLocated) locateEvidenceBody(entry);
    }
  }, true);

  function renderGrant(g, s) {
    const id = `g${g.number}`;
    const bound = g.notes.filter(n => n.kind === "caveat").length;
    const status = g.exact
      ? el("span", { class: "v-exact" }, "exact")
      : el("button", { type: "button", class: "ref v-unknown", "data-ref": `${id}-n1` }, `upper bound · ${bound} ${bound === 1 ? "caveat" : "caveats"}`);
    return el("article", { class: "answer", "aria-label": `grant ${g.number}` },
      el("h3", { class: "grant-head" },
        el("span", {}, `grant ${g.number}`),
        el("button", { type: "button", class: "ref stmt", "data-stmt": g.statement, "aria-pressed": "false" }, `statement[${g.statement}]${g.sid ? " " + g.sid : ""}`),
        el("span", { class: "muted" }, lineRange(s)),
        el("span", {}, g.effect),
        status),
      el("p", { class: "sentence" }, renderSpans(g.spans, id)),
      g.caption ? el("p", { class: "prose muted" }, g.caption) : null,
      g.terms.map((term, i) => renderTerm(term, i, g.terms.length, g.number)),
      g.notes.length ? renderNotes(id, g.notes, new Set(g.spans.map(s => s.note))) : null,
      g.witness ? renderWitness(g) : null,
      renderEvidence(g, [
        ["issuer", [g.issuer || "none: the principal could not be read", g.issuerWritten ? [", from ", g.issuerWritten.member, " on ", lineRef(g.issuerWritten.line)] : null]],
        ["effect", g.effect],
        ["target", "the role this policy is attached to; a trust policy does not name its own role"],
        ["admits", el("span", { class: "digest" }, g.admits)],
        ...caveatPairs(g),
      ]));
  }

  const lineRange = s => `L${s.firstLine}${s.lastLine !== s.firstLine ? "–" + s.lastLine : ""}`;
  const lineRef = n => el("button", { type: "button", class: "ref", "data-ref": `L${n}` }, `L${n}`);

  // a sentence's runs: a value in code, coloured by what the engine knows;
  // a run that refers to a note gets a superscript reference to it
  function renderSpans(spans, id) {
    const referenced = new Set();
    return spans.flatMap(s => {
      let node;
      if (s.mark === "code") node = el("code", {}, s.text);
      else if (s.mark === "exact") node = el("code", { class: "v-exact" }, s.text);
      else if (s.mark) node = el("span", { class: `v-${s.mark}` }, s.text);
      else node = document.createTextNode(s.text);
      if (!s.note || !id) return [node];
      const first = !referenced.has(s.note);
      referenced.add(s.note);
      return [node, el("sup", {}, el("button", { type: "button", class: "ref", id: first ? `${id}-r${s.note}` : null, "data-ref": `${id}-n${s.note}` }, String(s.note)))];
    });
  }

  // A term table is wider than a narrow pane and scrolls sideways in its own
  // box, so the box is a named region the keyboard can reach: a scroll box
  // with nothing focusable inside it is unreachable without a mouse.
  function renderTerm(term, i, of, number) {
    const rows = term.map(row => el("tr", {},
      el("td", {}, row.claim),
      el("td", { class: `val${row.mark ? " v-" + row.mark : ""}` }, row.rendered),
      el("td", { class: `words${row.mark === "unknown" ? " v-unknown" : ""}` }, row.words,
        row.note ? el("sup", {}, String(row.note)) : null,
        row.written.map(w => el("span", { class: "why" }, " · ", lineRef(w.line), ` ${w.operator || w.member || ""}`)))));
    rows.push(el("tr", { class: "rest" }, el("td", {}, "any other claim"), el("td", { class: "val" }, "any"), el("td", { class: "words" }, "unconstrained ", el("span", { class: "why" }, "· no condition names it"))));
    return [
      of > 1 ? el("p", { class: "label term-label" }, `term ${i + 1} of ${of}`) : null,
      el("div", { class: "table", role: "group", tabindex: "0", "aria-label": of > 1 ? `what grant ${number} admits, term ${i + 1} of ${of}` : `what grant ${number} admits` },
        el("table", { class: "terms" },
          el("thead", {}, el("tr", {}, el("th", { class: "label" }, "claim"), el("th", { class: "label" }, "admits"), el("th", { class: "label" }, "in words · as written"))),
          el("tbody", {}, rows))),
    ];
  }

  // caveats and anomalies, numbered so the sentence and the table can point
  // at them, each with every field the engine's types carry; a note the
  // sentence refers to links back to the reference
  function renderNotes(id, notes, referenced) {
    return el("ol", { class: "notes", "aria-label": "caveats and anomalies" }, notes.map(n => el("li", { id: `${id}-n${n.number}` },
      el("span", { class: "v-unknown" }, n.kind),
      el("span", { class: "kind" }, " ",
        n.anomaly ? ["· kind ", el("code", {}, n.anomaly), " "] : null,
        n.claim ? ["· claim ", el("code", {}, n.claim), " "] : null,
        n.construct ? ["· construct ", el("code", {}, n.construct), " "] : null,
        "· source ", el("code", {}, n.source)),
      el("br"),
      n.message,
      referenced.has(n.number) ? [" ", el("button", { type: "button", class: "ref", "data-ref": `${id}-r${n.number}`, "aria-label": "back to the sentence" }, "↩")] : null)));
  }

  // the witness, under the heading and the caption the engine wrote for it:
  // what the token proves is the engine's to say
  function renderWitness(g) {
    return el("section", { class: "witness" },
      el("h4", { class: "label" }, g.witnessHeading),
      el("pre", { class: "quote" }, g.witness),
      el("p", { class: "prose muted" }, `${g.witnessCaption} `, tokenLink("Try it in the token view", g.witness), ", or a token of your own."));
  }

  function caveatPairs(g) {
    const caveats = g.notes.filter(n => n.kind === "caveat");
    if (caveats.length === 0) return [["caveats", "none: the set is exact"]];
    return caveats.map(n => [el("span", { class: "v-unknown" }, "caveat"), [n.claim ? ["claim ", el("code", {}, n.claim), " · "] : null, n.message, " · source ", el("code", {}, n.source), ` (note ${n.number})`]]);
  }

  // evidence: the document, the statement's bytes located and digested, the
  // grant's facts, and the statement's own bytes quoted from the source;
  // open when the answer is a bound, because a reader told the set is a
  // bound is owed the bytes without a click. The grant's facts are built
  // with the grant; where the statement sits in the document is written by
  // locateEvidence, which a keystroke anywhere in the document changes.
  function renderEvidence(g, pairs) {
    return el("details", { class: "evidence", open: !g.exact },
      el("summary", {}, "", g.exact ? "" : " · open because the set is an upper bound"),
      el("dl", { class: "pairs" },
        el("dt", {}, "document"), el("dd"),
        el("dt", {}, "statement"), el("dd"),
        pairs.map(([dt, dd]) => [el("dt", {}, dt), el("dd", {}, dd)])),
      el("pre", { class: "quote" }));
  }

  // summariseEvidence and locateEvidence write what a keystroke moves: the
  // summary, always on screen; then the document's size and digest, the
  // statement's offset, lines and digest, and its bytes. The details element
  // itself is kept, so a reader's own opening or closing of it stays.
  function summariseEvidence(details, s) {
    details.firstElementChild.firstChild.textContent = `evidence · statement[${s.index}] · ${s.length} bytes at offset ${s.offset} · sha256 ${s.sha256.slice(0, 8)}…`;
  }
  function locateEvidence(details, s) {
    const doc = answer.document;
    const [, dl, pre] = details.children;
    summariseEvidence(details, s);
    dl.children[1].replaceChildren(`${doc.bytes} bytes as pasted, ${doc.lines} lines · sha256 `, el("span", { class: "digest" }, doc.sha256));
    dl.children[3].replaceChildren(`[${s.index}], bytes ${s.offset}–${s.offset + s.length - 1}, lines ${s.firstLine}–${s.lastLine} · sha256 `, el("span", { class: "digest" }, s.sha256), " · quoted below verbatim, never re-serialised");
    const bytes = statementBytes(s);
    if (pre.textContent !== bytes) pre.textContent = bytes;
  }

  // the statement's own bytes, cut from the pasted text at the byte offsets
  // the engine reported
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const bytesOf = text => encoder.encode(text).length;
  function statementBytes(s) {
    return decoder.decode(policyBytes.subarray(s.offset, s.offset + s.length));
  }

  // ---- the token view ----

  function renderTokenView() {
    let view = $(".answer.token-view", answerBody);
    if (!view) {
      view = template("t-token");
      view.classList.add("token-view");
      const textarea = $("textarea", view);
      textarea.value = state.token;
      textarea.addEventListener("input", () => {
        state.token = textarea.value;
        unreadableLink = "";
        oncePerFrame(() => {
          refresh();
          afterRender(() => writeFragment("replaceState"));
        });
      });
      view.append(el("div", { class: "outcomes" }));
    }
    const textarea = $("textarea", view);
    if (textarea.value !== state.token) textarea.value = state.token; // a link changed the state, not a keystroke
    const readable = answer && !answer.error;
    const inexact = readable && answer.grants.some(g => !g.exact);
    const witnessed = readable ? answer.grants.filter(g => g.witness) : [];
    const stopped = Boolean(explanation && explanation.stopped);
    const copy = {
      "no-policy": !readable,
      read: readable,
      bound: inexact,
      witness: readable && !state.token.trim() && witnessed.length > 0,
      "unreadable-token": Boolean(explanation && !stopped && explanation.token.error),
      stopped,
    };
    for (const p of $$("[data-copy]", view)) p.hidden = !copy[p.dataset.copy];
    showUnreadableLink(view);
    if (copy.witness) {
      $(".witness-links", view).replaceChildren(...witnessed.flatMap((g, i) => {
        const a = tokenLink(`grant ${g.number}'s witness`, g.witness);
        return i > 0 ? [", ", a] : [a];
      }));
    }
    if (copy["unreadable-token"]) $("[data-copy=unreadable-token] .error", view).textContent = explanation.token.error;
    if (stopped) $("[data-copy=stopped] .error", view).textContent = explanation.error;
    for (const a of $$("a[data-view]", view)) a.onclick = e => { e.preventDefault(); go({ view: a.dataset.view }); };
    const outcomes = $(".outcomes", view);
    const answered = explanation && !stopped && !explanation.token.error && !explanation.error;
    outcomes.replaceChildren(...(answered ? [renderPolicyOutcome(), ...explanation.grants.flatMap(renderOutcome)].filter(Boolean) : []));
    place(answerBody, [view, readable ? bridge() : null, teaching()].filter(Boolean));
  }

  // the policy's answer for the token, above its grants, when there is more
  // than one grant to weigh; with one, the grant's own section says it
  function renderPolicyOutcome() {
    if (explanation.grants.length < 2) return null;
    return el("section", { class: "token-answer", "aria-label": "answer for this token from the policy" },
      el("h3", {}, renderSpans(explanation.heading)),
      el("p", { class: "sentence" }, renderSpans(explanation.spans)));
  }

  // one grant's answer for the token: the heading, the sentence, every claim
  // of the token against the grant, and the evidence
  function renderOutcome(o) {
    const g = answer.grants[o.number - 1];
    const s = answer.document.statements[o.statement];
    const rows = o.claims.map(row => {
      const constraint = row.constraint.kind === "issuer"
        ? [`grant ${o.number}'s issuer`, row.written.map(w => [", ", lineRef(w.line)])]
        : [row.rendered, row.written.map(w => [" ", lineRef(w.line)])];
      const muted = row.result === "satisfies" || row.result === "not named";
      return el("tr", { class: row.result === "not named" && !row.mark ? "rest" : null },
        el("td", {}, row.claim),
        el("td", { class: "token-val" }, row.value),
        el("td", { class: `val${row.mark ? " v-" + row.mark : ""}` }, constraint),
        el("td", { class: `result${muted ? " muted" : ""}${row.result === "not evaluated" ? " v-unknown" : ""}` }, row.result));
    });
    const named = o.named.length ? `${prose(o.named)} ${o.named.length === 1 ? "is the one" : "are the ones"} grant ${o.number} names` : `grant ${o.number} names no claim`;
    const evidence = renderEvidence(g, [
      ["admits", el("span", { class: "digest" }, g.admits)],
      ...caveatPairs(g).filter(([dt]) => dt !== "caveats"),
      ["excludes", o.excludes ? el("span", { class: "digest" }, `claim=${o.excludes.claim} constraint=${o.excludes.constraint}`) : `nothing · admits=${o.admitted} · exact=${o.exact}`],
      ["token", `${explanation.token.claims} ${explanation.token.claims === 1 ? "claim" : "claims"} as pasted${explanation.token.decoded ? ", decoded from the whole token" : ""}; ${named}`],
    ]);
    locateEvidence(evidence, s);
    return [
      el("section", { class: "token-answer", "aria-label": `answer for this token from grant ${o.number}` },
        el("h3", {}, renderSpans(o.heading)),
        el("p", { class: "sentence" }, renderSpans(o.spans)),
        el("div", { class: "table", role: "group", tabindex: "0", "aria-label": `the token's claims against grant ${o.number}` },
          el("table", { class: "terms claims" },
            el("thead", {}, el("tr", {}, el("th", { class: "label" }, "claim"), el("th", { class: "label" }, "token"), el("th", { class: "label" }, `grant ${o.number} admits`), el("th", { class: "label" }, "result"))),
            el("tbody", {}, rows)))),
      evidence,
    ];
  }

  const prose = items => items.length <= 1 ? items.join("") : `${items.slice(0, -1).join(", ")} and ${items.at(-1)}`;
  const plain = spans => spans.map(s => s.text).join("");

  // ---- share: the address bar already holds the state; the row makes it a link ----

  const shareRow = $("#share");
  const shareUrl = $("#share-url");
  // the link's text is the whole answer: every grant's sentence, or the
  // policy's answer for the token, so that a reader of a pull request sees
  // what the page says, not its first line
  function shareText() {
    if (state.view === "token") return explanation && !explanation.error && !explanation.token.error ? plain(explanation.heading) : "";
    if (answer && !answer.error) return answer.grants.map(g => g.sentence).join(" ");
    return "";
  }
  // the row holds every grant's sentence and the whole address; while it is
  // closed none of that is on screen, and a keystroke need not spell it
  function renderShare() {
    if (shareRow.hidden) return;
    const summary = answerReadout.textContent.trim();
    const text = shareText();
    shareUrl.value = location.href;
    shareUrl.dataset.markdown = text ? `[${text}](${location.href})${summary ? " — cloudarq admits · " + summary : ""}` : "";
    $("#share-note").textContent = state.policy || state.token
      ? `${location.hash.length - 1} characters in the fragment: the policy${state.token ? " and the token" : ""}, sent nowhere.${text ? ` Markdown: [${text}](…)` : ""}`
      : "Nothing to share yet: nothing is pasted.";
  }
  $("#share-toggle").addEventListener("click", function () {
    shareRow.hidden = !shareRow.hidden;
    this.setAttribute("aria-expanded", String(!shareRow.hidden));
    if (!shareRow.hidden) { renderShare(); shareUrl.focus(); shareUrl.select(); }
  });
  // the button says what happened; without clipboard access the field is
  // selected instead, one keystroke from a copy
  function copy(text, button) {
    const idle = button.textContent;
    const say = word => { button.textContent = word; button.addEventListener("blur", () => { button.textContent = idle; }, { once: true }); };
    const select = () => { shareUrl.select(); say("select all, then copy"); };
    if (!navigator.clipboard) { select(); return; }
    navigator.clipboard.writeText(text).then(() => say("copied"), select);
  }
  $("#copy-url").addEventListener("click", function () { copy(location.href, this); });
  $("#copy-md").addEventListener("click", function () { copy(shareUrl.dataset.markdown || location.href, this); });

  // ---- theme: system by default; a choice lasts for this page load, because
  // the explorer keeps no storage of any kind ----

  const root = document.documentElement;
  const choices = $$("[data-theme-choice]");
  for (const b of choices) b.addEventListener("click", () => {
    const c = b.dataset.themeChoice;
    if (c === "system") delete root.dataset.theme; else root.dataset.theme = c;
    for (const o of choices) o.setAttribute("aria-pressed", String(o === b));
  });

  // ---- the divider: pointer drag, and arrow keys when focused; the split is
  // one custom property on <main>, its bounds read from the tokens ----

  const main = $("main");
  const tokens = getComputedStyle(root);
  const min = parseFloat(tokens.getPropertyValue("--pane-min"));
  const max = parseFloat(tokens.getPropertyValue("--pane-max"));
  const divider = $(".divider");
  let split = parseFloat(getComputedStyle(main).getPropertyValue("--split"));
  const setSplit = v => {
    split = Math.min(max, Math.max(min, Math.round(v)));
    main.style.setProperty("--split", split);
    divider.setAttribute("aria-valuenow", split);
  };
  divider.setAttribute("aria-valuemin", min);
  divider.setAttribute("aria-valuemax", max);
  divider.setAttribute("aria-valuenow", split);
  divider.addEventListener("keydown", e => {
    const step = e.shiftKey ? 10 : 2;
    const next = { ArrowLeft: split - step, ArrowRight: split + step, Home: min, End: max }[e.key];
    if (next === undefined) return;
    e.preventDefault();
    setSplit(next);
  });
  divider.addEventListener("pointerdown", e => {
    divider.setPointerCapture(e.pointerId);
    const box = main.getBoundingClientRect();
    const move = ev => setSplit((ev.clientX - box.left) / box.width * 100);
    divider.addEventListener("pointermove", move);
    divider.addEventListener("pointerup", () => divider.removeEventListener("pointermove", move), { once: true });
  });

  return readFragment;
}

if (typeof document !== "undefined") {
  const start = explorer();
  // the engine's sentence is for the engine's own failure to arrive; what
  // the page does with the address afterwards is answered on the page
  WebAssembly.compileStreaming(fetch(new URL("cloudarq.wasm", import.meta.url)))
    .then(loadEngine)
    .then(start, err => {
      document.querySelector("#answer-readout").textContent = `the engine did not load: ${err.message}`;
      document.querySelector("#policy-readout").textContent = "";
    });
}
