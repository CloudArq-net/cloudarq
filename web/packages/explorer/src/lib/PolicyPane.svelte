<!--
  The policy pane: the paste box, or the pasted document as numbered lines
  with a mark on the first line of each statement and a rule beside the lines
  it spans.

  The listing is the input and stays quiet: every line's source is ink-2,
  selected or not. The selection is carried by the statement's mark and by the
  rule beside its line numbers, which is what the grant head says on the other
  side of the divider.
-->
<script lang="ts">
	import type { Answer, DocumentReport } from "./answer.ts";
	import { explorer } from "./context.ts";

	interface Props {
		/** The document as pasted. */
		policy: string;
		/** The engine's answer for it, or null when nothing is pasted. */
		answer: Answer | null;
		/** The readout in the pane head. */
		readout: string;
		/** Whether the pane shows the box rather than the listing. */
		editing: boolean;
		/** Whether a readable answer exists, so the pane can be toggled. */
		toggleable: boolean;
		/** What the control that empties the pane is called here. */
		clearLabel: string;
		/** The address of the empty state. */
		clearHref: string;
		/** The statement indices selected in both panes. */
		selected: Set<number>;
		ontoggle: () => void;
		onclear: () => void;
		oninput: (policy: string) => void;
	}
	let { policy, answer, readout, editing, toggleable, clearLabel, clearHref, selected, ontoggle, onclear, oninput }: Props = $props();

	// A line of the listing is the target of a reference from the other pane,
	// so its name is this explorer's, like every other name here.
	const { id, landmark } = explorer();

	const doc = $derived(answer && !answer.error ? (answer.document as DocumentReport) : null);
	const listing = $derived(Boolean(doc) && !editing);

	interface Line {
		number: number;
		text: string;
		/** The statements this line falls inside, as the attribute spells them. */
		within: string | undefined;
		/** Whether any of those statements is selected. */
		selected: boolean;
		/** The statement that opens on this line, if one does. */
		opens: { index: number; sid: string; firstLine: number; lastLine: number } | null;
	}

	const lines = $derived.by((): Line[] => {
		if (!doc) return [];
		const text = policy.split("\n");
		if (text.at(-1) === "") text.pop();
		const within = new Map<number, number[]>();
		const starts = new Map<number, Line["opens"]>();
		for (const s of doc.statements) {
			for (let n = s.firstLine; n <= s.lastLine; n++) within.set(n, [...(within.get(n) ?? []), s.index]);
			if (!starts.has(s.firstLine)) starts.set(s.firstLine, s);
		}
		return text.map((line, i) => {
			const n = i + 1;
			const inside = within.get(n);
			return {
				number: n,
				text: line,
				within: inside ? inside.join(" ") : undefined,
				selected: Boolean(inside?.some((index) => selected.has(index))),
				opens: starts.get(n) ?? null,
			};
		});
	});

	let box = $state<HTMLTextAreaElement | null>(null);
	// The box is written only when its text is not already the document: a
	// keystroke's own text is already in it, and assigning the same string back
	// moves the caret. A link that changed the state is the case this is for.
	$effect(() => {
		if (box && box.value !== policy) box.value = policy;
	});
	/** focusBox puts the keyboard in the paste box. The control that empties the
	 *  pane hides itself — there is nothing left to clear — so a reader who
	 *  pressed it would otherwise be dropped at the top of the page. */
	export function focusBox(): void {
		box?.focus();
	}
</script>

<section class="pane" id={id("policy-pane")} aria-label={landmark() ? "policy" : undefined}>
	<div class="pane-head">
		<h2 class="label">policy</h2>
		<span class="readout" id={id("policy-readout")}>{readout}</span>
		<span class="pane-links"><button type="button" class="ref" id={id("policy-edit")} hidden={!toggleable} onclick={ontoggle}>{listing ? "edit" : "listing"}</button><a href={clearHref} id={id("policy-clear")} hidden={!policy} onclick={(e) => { e.preventDefault(); onclear(); }}>{clearLabel}</a></span>
	</div>
	<div class="pane-body" id={id("policy-body")}>
		{#if listing}
			<div class="policy" role={landmark() ? "region" : undefined} aria-label={landmark() ? "the policy as pasted, with line numbers and statement marks" : undefined}>
				{#each lines as line (line.number)}<div id={id(`L${line.number}`)} class="l" data-in={line.within} data-selected={line.selected ? "" : undefined}>{#if line.opens}<button class="mark" type="button" data-stmt={line.opens.index} aria-pressed={selected.has(line.opens.index)} aria-label="statement {line.opens.index}, {line.opens.sid || 'no Sid'}, lines {line.opens.firstLine} to {line.opens.lastLine}">[{line.opens.index}]</button>{:else}<span class="mark"></span>{/if}<span class="ln">{line.number}</span><span class="src">{line.text}</span></div>{/each}
			</div>
		{:else}
			<div class="paste">
				<textarea bind:this={box} name="policy" aria-label="trust policy" placeholder="Paste a trust policy. The answer appears as you type." spellcheck="false" oninput={(e) => oninput(e.currentTarget.value)}></textarea>
				<dl class="pairs accepts" hidden={Boolean(policy)}>
					<dt>aws</dt><dd>a role's trust policy: Statement, Principal.Federated, Condition</dd>
				</dl>
			</div>
		{/if}
	</div>
</section>
