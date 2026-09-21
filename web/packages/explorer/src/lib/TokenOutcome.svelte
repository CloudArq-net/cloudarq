<!--
  One grant's answer for the token: the heading, the sentence, every claim of
  the token against the grant, and the evidence. A claim the grant does not
  name is listed and ignored rather than dropped — a claim that disappeared
  would read as a claim that was checked.

  Spaces that carry meaning are written as expressions; see TermTable.svelte.
-->
<script lang="ts">
	import CaveatPairs from "./CaveatPairs.svelte";
	import EvidenceBlock from "./EvidenceBlock.svelte";
	import LineRef from "./LineRef.svelte";
	import Spans from "./Spans.svelte";
	import type { DocumentReport, Grant, Outcome, Statement, TokenReport } from "./answer.ts";
	import { explorer } from "./context.ts";

	interface Props {
		outcome: Outcome;
		/** The grant the outcome is about, from the policy's own answer. */
		grant: Grant;
		statement: Statement;
		doc: DocumentReport;
		policyBytes: Uint8Array;
		token: TokenReport;
	}
	let { outcome, grant, statement, doc, policyBytes, token }: Props = $props();

	// a region is a landmark only where the explorer is the page
	const { landmark } = explorer();

	/** prose joins a list the way a sentence does: "a, b and c". */
	const prose = (items: string[]): string => (items.length <= 1 ? items.join("") : `${items.slice(0, -1).join(", ")} and ${items.at(-1)}`);

	const named = $derived(
		outcome.named.length
			? `${prose(outcome.named)} ${outcome.named.length === 1 ? "is the one" : "are the ones"} grant ${outcome.number} names`
			: `grant ${outcome.number} names no claim`,
	);
</script>

<section class="token-answer" aria-label={landmark() ? `answer for this token from grant ${outcome.number}` : undefined}>
	<h3><Spans spans={outcome.heading} /></h3>
	<p class="sentence"><Spans spans={outcome.spans} /></p>
	<!-- The table is wider than a narrow pane and scrolls sideways in its own
     box. A scroll box with nothing focusable inside it cannot be scrolled
     without a mouse, so the box itself is a named region the keyboard
     reaches. -->
<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
<div class="table" role="group" tabindex="0" aria-label="the token's claims against grant {outcome.number}">
		<table class="terms claims">
			<thead><tr><th class="label">claim</th><th class="label">token</th><th class="label">grant {outcome.number} admits</th><th class="label">result</th></tr></thead>
			<tbody>
				{#each outcome.claims as row (row.claim)}<tr class={row.result === "not named" && !row.mark ? "rest" : undefined}><td>{row.claim}</td><td class="token-val">{row.value}</td><td class="val{row.mark ? ' v-' + row.mark : ''}">{#if row.constraint.kind === "issuer"}{`grant ${outcome.number}'s issuer`}{#each row.written as w (w.line)}{", "}<LineRef line={w.line} />{/each}{:else}{row.rendered}{#each row.written as w (w.line)}{" "}<LineRef line={w.line} />{/each}{/if}</td><td class="result{row.result === 'satisfies' || row.result === 'not named' ? ' muted' : ''}{row.result === 'not evaluated' ? ' v-unknown' : ''}">{row.result}</td></tr>{/each}
			</tbody>
		</table>
	</div>
</section>
<EvidenceBlock {statement} {doc} {policyBytes} exact={grant.exact} writeWhileClosed>
	{#snippet extra()}
		<dt>admits</dt><dd><span class="digest">{grant.admits}</span></dd>
		<CaveatPairs notes={grant.notes} showNone={false} />
		<dt>excludes</dt><dd>{#if outcome.excludes}<span class="digest">{`claim=${outcome.excludes.claim} constraint=${outcome.excludes.constraint}`}</span>{:else}{`nothing · admits=${outcome.admitted} · exact=${outcome.exact}`}{/if}</dd>
		<dt>token</dt><dd>{`${token.claims} ${token.claims === 1 ? "claim" : "claims"} as pasted${token.decoded ? ", decoded from the whole token" : ""}; ${named}`}</dd>
	{/snippet}
</EvidenceBlock>
