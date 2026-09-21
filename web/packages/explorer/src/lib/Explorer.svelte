<!--
  The explorer. The page is a function of the fragment, the engine is the
  answer package compiled to WebAssembly, and nothing here evaluates: every
  sentence, value and number on screen comes from the engine's admits() and
  explain() or from the copy in these components.

  The component does not load the engine and does not name a URL for it: the
  host compiles the bytes and hands the engine over, so `connect-src 'self'`
  is literally true on whichever origin serves them, and two explorers on one
  page share one instance rather than each starting a heap of their own.

  Two on one page is the case the defaults are written for. Every element id
  is spelt inside the instance and a landmark is named only where the host
  says this explorer is the page (context.ts), the address is read and
  written only where the host says so, and everything an instance scheduled
  is cancelled when it is unmounted.
-->
<script lang="ts">
	import { flushSync, untrack } from "svelte";

	import AnswerPane from "./AnswerPane.svelte";
	import Divider from "./Divider.svelte";
	import PolicyPane from "./PolicyPane.svelte";
	import ShareRow from "./ShareRow.svelte";
	import type { Answer, DocumentReport, Explanation, Grant } from "./answer.ts";
	import type { Engine } from "./engine.ts";
	import { ANSWER_VERSION } from "./answer.ts";
	import { exampleNamed, examples, exampleText, openingDocument } from "./examples.ts";
	import { buildFragment, deflate, parseFragment, readFragment, type Decoded, type View } from "./fragment.ts";
	import { provideExplorer } from "./context.ts";

	interface Props {
		/** The engine, or null while it is still being compiled. */
		engine: Engine | null;
		/** What the host has to say when the engine did not arrive. The engine's
		 *  own failure keeps its own sentence; what the page does with the
		 *  address afterwards is answered on the page. */
		engineError?: string;
		/** Whether this explorer reads and writes the page's address. At most
		 *  one on a page may: two that both wrote location.hash would fight
		 *  over it, and the address would name one document while the other
		 *  pane showed another. It is off by default because the address is the
		 *  page's and an embedded explorer is a part of a page, not the page.
		 *  The opening document does not depend on it. */
		ownsAddress?: boolean;
		/** Whether this explorer is the page's main content. It renders <main>
		 *  rather than a plain element, and its panes are named regions. At
		 *  most one on a page may: two main landmarks are two answers to
		 *  "where does this page begin", and two panes both named "policy"
		 *  are two landmarks a reader cannot tell apart. An explorer embedded
		 *  in someone else's page adds no landmark to it. */
		landmark?: boolean;
		/** Whether the share row is open. The host's own bar carries the control
		 *  that opens it, because the bar is the page's and not the explorer's.
		 *  It has nothing to open where this explorer does not own the address:
		 *  the row offers the address as a link, and an explorer that does not
		 *  write one has none to offer, so the row is not rendered there. */
		shareOpen?: boolean;
	}
	let { engine, engineError = "", ownsAddress = false, landmark = false, shareOpen = $bindable(false) }: Props = $props();

	// Every id this explorer renders is spelt under this instance's name, and
	// every region it names is a landmark only where this explorer is the page.
	const uid = $props.id();
	const { id } = provideExplorer(uid, () => landmark);
	/** shareId names the share row, for a host whose own bar carries the
	 *  control that opens it: aria-controls has to name the element the
	 *  control produces, and the element belongs to this instance. It is empty
	 *  where this explorer does not own the address, because there is no row —
	 *  and a control pointing at an id no element carries is a control that
	 *  describes nothing. Read once, and untracked to say so: whether an
	 *  explorer owns the page's address is what it is for the life of the
	 *  mount, and an exported const could not follow it anyway. */
	export const shareId = untrack(() => ownsAddress) ? id("share") : "";

	let dialect = $state("aws");
	let policy = $state("");
	let token = $state("");
	let view = $state<View>("admits");
	/** The policy pane shows the box rather than the listing. */
	let editing = $state(false);
	/** Why the address's fragment could not be read, when it could not. */
	let unreadableLink = $state("");
	/** Whether the address has been read at least once. Until it has, the page
	 *  is still loading and says so rather than saying nothing is pasted. */
	let addressRead = $state(false);

	const encoder = new TextEncoder();
	// $state.raw throughout for the engine's answers and the pasted bytes: they
	// are replaced whole on every keystroke and never edited in place, and deep
	// proxying a fifty-grant answer is work inside the frame the answer has to
	// land in.
	const policyBytes = $derived.by(() => encoder.encode(policy));

	// answerOf reads one answer from the engine. An engine that stops is
	// answered for, so that the previous answer never stays on screen for a
	// document it was not about.
	function answerOf<T extends { v: number; error?: string; stopped?: boolean; grants: unknown[] }>(ask: () => string, empty: Omit<T, "v" | "error" | "stopped">): T {
		let text: string;
		try {
			text = ask();
		} catch (err) {
			return { v: ANSWER_VERSION, stopped: true, error: (err as Error).message, ...empty } as T;
		}
		const parsed = JSON.parse(text) as T;
		if (parsed.v !== ANSWER_VERSION) {
			return { v: parsed.v, error: `the engine answered with version ${parsed.v}; this page reads version ${ANSWER_VERSION}`, ...empty } as T;
		}
		return parsed;
	}

	const answer = $derived.by((): Answer | null => {
		if (!engine || !policy.trim()) return null;
		return answerOf<Answer>(() => engine.admits(policy), { grants: [] });
	});
	const readable = $derived(Boolean(answer) && !answer!.error);
	const doc = $derived(readable ? (answer!.document as DocumentReport) : null);
	const explanation = $derived.by((): Explanation | null => {
		if (!engine || !readable || view !== "token" || !token.trim()) return null;
		return answerOf<Explanation>(() => engine.explain(policy, token), { token: { decoded: false, claims: 0 }, heading: [], sentence: "", spans: [], grants: [] });
	});

	// A keystroke changes one statement's grant and every later statement's byte
	// offset. Forty-nine of fifty grants then say exactly what they said
	// before, so a grant that reads the same keeps its object identity and the
	// component leaves its article alone; without this, every text node of
	// every grant is written again on every keystroke, which is most of the
	// frame the answer has to land in. The map is a plain variable and not
	// state: it is a cache of the last render, not a fact about the document.
	let remembered = new Map<number, { key: string; grant: Grant }>();
	const grants = $derived.by((): Grant[] => {
		if (!answer || answer.error) {
			remembered = new Map();
			return [];
		}
		const next = new Map<number, { key: string; grant: Grant }>();
		const list = answer.grants.map((fresh) => {
			const key = JSON.stringify(fresh);
			const kept = remembered.get(fresh.number);
			const grant = kept && kept.key === key ? kept.grant : fresh;
			next.set(fresh.number, { key, grant });
			return grant;
		});
		remembered = next;
		return list;
	});

	// A selection belongs to one document: a document of one statement opens
	// with it selected, so the tint and the rule that join the panes are on
	// screen before anything is pressed, and a new document starts again.
	let chosen = $state.raw<{ policy: string; set: Set<number> } | null>(null);
	// The set keeps its identity while its members do, for the same reason the
	// grants do: a keystroke is a new document and a new set, and handing the
	// same members back under a new object rewrites aria-pressed on every
	// statement mark and every grant head for nothing.
	let lastSelected = new Set<number>();
	const selected = $derived.by((): Set<number> => {
		let next: Set<number>;
		if (chosen && chosen.policy === policy) {
			next = chosen.set;
		} else {
			next = new Set<number>();
			if (doc && doc.statements.length === 1) next.add(0);
		}
		if (next.size === lastSelected.size && [...next].every((n) => lastSelected.has(n))) return lastSelected;
		lastSelected = next;
		return next;
	});

	// ---- the readouts ----

	const policyReadout = $derived.by(() => {
		if (engineError) return "";
		if (!engine || !addressRead) return "loading the engine";
		if (!policy.trim()) return "nothing pasted";
		if (answer!.error) return `${dialect} · ${encoder.encode(policy).length} bytes · not read`;
		const n = doc!.statements.length;
		// the case number is what the pane head has room for; the teaching block
		// under the answer spells the case out
		const named = exampleNamed(policy).split("-")[0];
		return `${dialect} trust policy · ${doc!.bytes} bytes · ${n} ${n === 1 ? "statement" : "statements"}${named ? ` · example ${named}` : ""}`;
	});

	const answerReadout = $derived.by((): { head: string; rest: string; mark: string } => {
		if (engineError) return { head: `the engine did not load: ${engineError}`, rest: "", mark: "" };
		if (!answer || answer.error) return { head: "", rest: "", mark: "" };
		const grants = answer.grants;
		const caveats = grants.reduce((n, g) => n + g.notes.filter((note) => note.kind === "caveat").length, 0);
		const head = `${grants.length} ${grants.length === 1 ? "grant" : "grants"} · `;
		if (grants.length === 0) return { head: `${head}nobody is named`, rest: "", mark: "" };
		if (caveats === 0) return { head, rest: "exact", mark: "v-exact" };
		const bounds = grants.filter((g) => !g.exact).length;
		return { head, rest: `${bounds === grants.length ? "" : bounds + " "}upper bound · ${caveats} ${caveats === 1 ? "caveat" : "caveats"}`, mark: "v-unknown" };
	});

	// ---- the address ----

	// `encoded` is the state as the fragment spells it, kept so that every link
	// can be spelt from it by concatenation: the policy is deflated once per
	// change, not once per link. On a fifty-grant answer a keystroke would
	// otherwise write fifty witness links twice, once with the fragment of the
	// document as it was a keystroke ago.
	let encoded = $state.raw({ dialect: "aws", policy: "", token: "" });
	let href = $state("");
	const hrefOf = (next: { view?: View; token?: string }) => buildFragment({ ...encoded, ...next });
	const viewHrefs = $derived({ admits: hrefOf({ view: "admits" }), token: hrefOf({ view: "token" }) });
	const fragment = $derived(buildFragment({ ...encoded, view }));

	let writes = 0;
	async function writeAddress(how: "pushState" | "replaceState"): Promise<void> {
		const turn = ++writes;
		const [nextPolicy, nextToken] = await Promise.all([deflate(policy), deflate(token)]);
		if (turn !== writes || gone) return; // a later write already holds the newer state, or there is no explorer left to spell one
		encoded = { dialect, policy: nextPolicy, token: nextToken };
		if (!ownsAddress) return;
		history[how](null, "", location.pathname + location.search + buildFragment({ ...encoded, view }));
		href = location.href;
	}

	// readAddress loads the state a link carries. A fragment that cannot be
	// read, which is what a link cut short when it was copied looks like, loads
	// nothing and says so; the page never shows an answer under an address it
	// did not come from. An explorer that does not own the address reads none
	// and opens with the same document a page whose address carries nothing
	// opens with: the opening document is the explorer's empty state, and an
	// embedded explorer has one too.
	let reads = 0;
	async function readAddress(): Promise<void> {
		const turn = ++reads;
		const hash = ownsAddress ? location.hash : "";
		if (!hash) {
			// where this explorer owns the address, the opening document writes
			// its own before it renders, so that the view links, the witness
			// links and the share row carry the state a reader can copy, and the
			// page is its own shared link
			const text = exampleText(openingDocument);
			const deflated = await deflate(text);
			if (turn !== reads || gone) return;
			dialect = "aws";
			policy = text;
			token = "";
			view = "admits";
			encoded = { dialect: "aws", policy: deflated, token: "" };
			unreadableLink = "";
			editing = false;
			if (ownsAddress) {
				history.replaceState(null, "", location.pathname + location.search + buildFragment({ ...encoded, view: "admits" }));
				href = location.href;
			}
			addressRead = true;
			return;
		}
		const spelt = parseFragment(hash);
		let read: Decoded | null = null;
		let why = "";
		try {
			read = await readFragment(hash);
		} catch (err) {
			why = (err as Error).message.includes("this page reads v1")
				? (err as Error).message
				: "it is not the deflated text this page writes, which is what a link cut short when it was copied looks like";
		}
		if (turn !== reads || gone) return;
		if (read) {
			dialect = read.dialect;
			policy = read.policy;
			token = read.token;
			view = read.view;
			encoded = { dialect: spelt.dialect, policy: spelt.policy, token: spelt.token };
			unreadableLink = "";
		} else {
			dialect = "aws";
			policy = "";
			token = "";
			view = "admits";
			encoded = { dialect: "aws", policy: "", token: "" };
			unreadableLink = why;
		}
		editing = false;
		href = location.href;
		addressRead = true;
	}

	function go(next: Partial<Decoded>): void {
		if (next.dialect !== undefined) dialect = next.dialect;
		if (next.policy !== undefined) policy = next.policy;
		if (next.token !== undefined) token = next.token;
		if (next.view !== undefined) view = next.view;
		editing = false;
		unreadableLink = "";
		// the answer is on screen before the address catches up with it: the
		// address is deflated in a task of its own
		flushSync();
		void writeAddress("pushState");
	}

	$effect(() => {
		void readAddress();
		if (!ownsAddress) return;
		const onhashchange = () => void readAddress();
		addEventListener("hashchange", onhashchange);
		return () => removeEventListener("hashchange", onhashchange);
	});

	// ---- the links whose target is a state of its own ----

	// Each of these is the whole address for a state this page can be in, so
	// hovering, copying the address and opening in a new tab all see that
	// state. They are deflated once per change rather than once per render.
	let exampleHrefs = $state.raw<Record<string, string>>({});
	$effect(() => {
		let live = true;
		void Promise.all(examples.map(async (e) => [e.name, buildFragment({ dialect, policy: await deflate(e.text), token: "", view: "admits" })] as const)).then((pairs) => {
			if (live) exampleHrefs = Object.fromEntries(pairs);
		});
		return () => {
			live = false;
		};
	});

	let witnessHrefs = $state.raw<Record<number, string>>({});
	$effect(() => {
		const grants = answer && !answer.error ? answer.grants.filter((g) => g.witness) : [];
		const spelling = encoded;
		let live = true;
		void Promise.all(grants.map(async (g) => [g.number, buildFragment({ ...spelling, token: await deflate(g.witness as string), view: "token" })] as const)).then((pairs) => {
			if (live) witnessHrefs = Object.fromEntries(pairs);
		});
		return () => {
			live = false;
		};
	});

	const clearHref = $derived(buildFragment({ dialect, policy: "", token: "", view: "admits" }));
	const clearLabel = $derived(exampleNamed(policy) ? "paste your own" : "clear");

	// ---- a keystroke is answered where it is heard ----

	// The browser's next frame is up to one display interval away — 16.7 ms on
	// a 60 Hz screen — and the re-evaluation fits inside that wait rather than
	// queueing behind it, so the answer lands in the frame the keystroke
	// arrived for instead of the one after. A second keystroke before the
	// browser has rendered would be a second whole re-evaluation inside one
	// frame, so that one waits for the frame the first already asked for.
	let rendering = false;
	let waiting: (() => void) | null = null;
	let frame: number | undefined;
	function oncePerFrame(work: () => void): void {
		if (rendering) {
			waiting = work;
			return;
		}
		rendering = true;
		frame = requestAnimationFrame(() => {
			rendering = false;
			frame = undefined;
			const later = waiting;
			waiting = null;
			later?.();
		});
		work();
	}

	// afterRender runs the work the answer does not wait for — the address
	// bar's update — in a task after the frame has painted: deflating the
	// document and writing the address measured at 0.8 ms inside the frame,
	// and a reader looks at the answer, not the address.
	let later: ReturnType<typeof setTimeout> | undefined;
	function afterRender(work: () => void): void {
		clearTimeout(later);
		later = setTimeout(work);
	}

	// Nothing an explorer scheduled outlives it. The address write is a task
	// of its own and an overtaken keystroke is a frame of its own, so an
	// explorer unmounted in between would rewrite location.hash about a
	// second later, for a document nobody is looking at, in a page that no
	// longer holds the explorer that spelt it. `gone` is what the two writes
	// that resume after an await read, because a cancelled timer cannot stop
	// a promise that has already been handed its continuation.
	let gone = false;
	$effect(() => () => {
		gone = true;
		clearTimeout(later);
		if (frame !== undefined) cancelAnimationFrame(frame);
		waiting = null;
	});

	let panes = $state<HTMLElement | null>(null);
	let pane = $state<{ focusBox: () => void } | null>(null);
	let share = $state<{ focusField: () => void } | null>(null);

	/** focusShareField selects the whole address. The host's bar owns the
	 *  control that opens the row, so it is the host that has to be able to put
	 *  the keyboard in the field the control exists to produce. */
	export function focusShareField(): void {
		share?.focusField();
	}

	// the box's own text, which is ahead of the document whenever a keystroke
	// has been overtaken inside a frame
	let draft = "";
	function onpolicyinput(value: string): void {
		const fresh = policy === "";
		draft = value;
		oncePerFrame(() => {
			policy = draft;
			editing = true;
			unreadableLink = "";
			// a paste into an empty box lands as the listing, and the keyboard
			// lands with it, on the first statement's mark; typing stays in the box
			const landing = fresh && readable;
			if (landing) editing = false;
			flushSync();
			if (landing) {
				const inThisExplorer = (name: string) => `[id="${CSS.escape(id(name))}"]`;
				const mark = panes?.querySelector<HTMLElement>(`${inThisExplorer("policy-body")} button.mark[data-stmt]`) ?? panes?.querySelector<HTMLElement>(inThisExplorer("policy-edit"));
				mark?.focus();
			}
			afterRender(() => void writeAddress("replaceState"));
		});
	}

	function ontokeninput(value: string): void {
		oncePerFrame(() => {
			token = value;
			unreadableLink = "";
			flushSync();
			afterRender(() => void writeAddress("replaceState"));
		});
	}

	function select(index: number, on: boolean): void {
		const set = new Set(selected);
		if (on) set.add(index);
		else set.delete(index);
		chosen = { policy, set };
	}

	// A statement mark in the gutter and the statement's name in a grant head
	// are one control: pressing either selects the statement and its grants in
	// both panes and brings the counterpart into view. A reference marks one
	// line or note and brings it into view; the mark is not state and is not in
	// the link, which is why it is written onto the element rather than held.
	// The listener is attached rather than written on the element: <main> is not
	// an interactive element and must not be given the keyboard semantics of
	// one. Every control this hears from — a statement mark, a grant head, a
	// line reference — is a <button>, so Enter and Space already reach it and
	// the click that arrives here is the button's own.
	$effect(() => {
		const on = panes;
		if (!on) return;
		on.addEventListener("click", onpaneclick);
		return () => on.removeEventListener("click", onpaneclick);
	});

	function onpaneclick(e: MouseEvent): void {
		const from = e.target as HTMLElement | null;
		if (!from || !panes) return;
		const statement = from.closest<HTMLElement>("[data-stmt]");
		if (statement) {
			const index = Number(statement.dataset.stmt);
			const on = !selected.has(index);
			select(index, on);
			if (!on) return;
			for (const other of panes.querySelectorAll<HTMLElement>(`[data-stmt="${index}"]`)) {
				if (other !== statement) other.scrollIntoView({ block: "nearest" });
			}
			return;
		}
		const reference = from.closest<HTMLElement>("[data-ref]");
		if (!reference?.dataset.ref) return;
		const target = panes.querySelector<HTMLElement>(`[id="${CSS.escape(reference.dataset.ref)}"]`);
		if (!target) return;
		for (const marked of panes.querySelectorAll<HTMLElement>("[data-mark]")) delete marked.dataset.mark;
		target.dataset.mark = "";
		target.scrollIntoView({ block: "nearest" });
	}

	// ---- what the share row says ----

	const plain = (spans: { text: string }[]) => spans.map((s) => s.text).join("");
	const answerText = $derived.by(() => {
		if (view === "token") return explanation && !explanation.error && !explanation.token.error ? plain(explanation.heading) : "";
		if (readable) return answer!.grants.map((g) => g.sentence).join(" ");
		return "";
	});
	const summary = $derived((answerReadout.head + answerReadout.rest).trim());
</script>

<!-- The row is the address, made copyable. Only the explorer that owns the
     address has one to copy: href is written where the address is written, so
     an embedded explorer's row would offer a link with nothing inside its
     parentheses. -->
{#if ownsAddress}
	<ShareRow
		bind:this={share}
		open={shareOpen}
		{href}
		{answerText}
		{summary}
		fragmentLength={Math.max(0, fragment.length - 1)}
		pasted={Boolean(policy || token)}
		withToken={Boolean(token)}
	/>
{/if}
<svelte:element this={landmark ? "main" : "div"} class="panes" bind:this={panes}>
	<PolicyPane
			bind:this={pane}
			{policy}
			{answer}
			readout={policyReadout}
			{editing}
			toggleable={readable}
			{clearLabel}
			{clearHref}
			{selected}
			ontoggle={() => (editing = !editing)}
			onclear={() => {
				go({ policy: "", token: "", view: "admits" });
				flushSync();
				pane?.focusBox();
			}}
			oninput={onpolicyinput}
		/>
		<Divider grid={panes} />
		<AnswerPane
			{view}
			{answer}
			{grants}
			{explanation}
			{token}
			{policyBytes}
			{selected}
			{unreadableLink}
			readout={answerReadout}
			{viewHrefs}
			{exampleHrefs}
			{witnessHrefs}
			onview={(next) => go({ view: next })}
			onexample={(name) => go({ policy: exampleText(name), token: "", view: "admits" })}
			onwitness={(witness) => go({ token: witness, view: "token" })}
			ontoken={ontokeninput}
		/>
	</svelte:element>
