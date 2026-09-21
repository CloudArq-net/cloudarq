<!--
  One grant: who a statement admits, said in a sentence, then each claim with
  the values it admits, then a decoded token the grant accepts, then the
  statement's own bytes.

  The head's statement name and the mark in the policy gutter are one control:
  pressing either selects the statement and its grants in both panes.

  Spaces that carry meaning are written as expressions; see TermTable.svelte.
-->
<script lang="ts">
	import CaveatPairs from "./CaveatPairs.svelte";
	import EvidenceBlock from "./EvidenceBlock.svelte";
	import LineRef from "./LineRef.svelte";
	import NoteList from "./NoteList.svelte";
	import Spans from "./Spans.svelte";
	import TermTable from "./TermTable.svelte";
	import type { DocumentReport, Grant, Statement } from "./answer.ts";
	import { explorer } from "./context.ts";

	interface Props {
		grant: Grant;
		statement: Statement;
		doc: DocumentReport;
		policyBytes: Uint8Array;
		/** Whether the grant's statement is selected in both panes. */
		selected: boolean;
		/** The address of the token view over this grant's witness, or "#" until
		 *  the witness has been deflated. */
		witnessHref: string;
		/** Follow the witness link without a document load. */
		onwitness: (witness: string) => void;
	}
	let { grant, statement, doc, policyBytes, selected, witnessHref, onwitness }: Props = $props();

	// A grant's notes and the references into them are named under the
	// explorer that rendered them, not under the document.
	const { id: name } = explorer();
	const id = $derived(name(`g${grant.number}`));
	const caveats = $derived(grant.notes.filter((n) => n.kind === "caveat").length);
	const lineRange = $derived(`L${statement.firstLine}${statement.lastLine !== statement.firstLine ? "–" + statement.lastLine : ""}`);
	const referenced = $derived(new Set(grant.spans.map((s) => s.note).filter((n): n is number => typeof n === "number")));
</script>

<article class="answer" aria-label="grant {grant.number}">
	<h3 class="grant-head"><span>grant {grant.number}</span><button type="button" class="ref stmt" data-stmt={grant.statement} aria-pressed={selected}>statement[{grant.statement}]{grant.sid ? " " + grant.sid : ""}</button><span class="muted">{lineRange}</span><span>{grant.effect}</span>{#if grant.exact}<span class="v-exact">exact</span>{:else}<button type="button" class="ref v-unknown" data-ref="{id}-n1">upper bound · {caveats} {caveats === 1 ? "caveat" : "caveats"}</button>{/if}</h3>
	<p class="sentence"><Spans spans={grant.spans} {id} /></p>
	{#if grant.caption}<p class="prose muted">{grant.caption}</p>{/if}
	{#each grant.terms as term, i (i)}<TermTable {term} index={i + 1} of={grant.terms.length} number={grant.number} />{/each}
	{#if grant.notes.length}<NoteList {id} notes={grant.notes} {referenced} />{/if}
	{#if grant.witness}
		<section class="witness">
			<h4 class="label">{grant.witnessHeading}</h4>
			<pre class="quote">{grant.witness}</pre>
			<p class="prose muted">{grant.witnessCaption + " "}<a href={witnessHref} onclick={(e) => { e.preventDefault(); onwitness(grant.witness ?? ""); }}>Try it in the token view</a>{", or a token of your own."}</p>
		</section>
	{/if}
	<EvidenceBlock {statement} {doc} {policyBytes} exact={grant.exact}>
		{#snippet extra()}
			<dt>issuer</dt><dd>{grant.issuer || "none: the principal could not be read"}{#if grant.issuerWritten}{", from " + grant.issuerWritten.member + " on "}<LineRef line={grant.issuerWritten.line} />{/if}</dd>
			<dt>effect</dt><dd>{grant.effect}</dd>
			<dt>target</dt><dd>the role this policy is attached to; a trust policy does not name its own role</dd>
			<dt>admits</dt><dd><span class="digest">{grant.admits}</span></dd>
			<CaveatPairs notes={grant.notes} />
		{/snippet}
	</EvidenceBlock>
</article>
