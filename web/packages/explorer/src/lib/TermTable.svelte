<!--
  What a grant admits, claim by claim: the lattice element in the engine's
  canonical rendering, the same thing in words, and where in the document it
  was written. The last row is the rest of the token: a claim no condition
  names is unconstrained, and saying so is the whole finding on most
  documents.

  A term table is wider than a narrow pane and scrolls sideways in its own
  box, so the box is a named region the keyboard can reach: a scroll box with
  nothing focusable inside it is unreachable without a mouse.

  Spaces that carry meaning are written as expressions — {" · "} rather than a
  literal — because the compiler is free to collapse literal whitespace in
  markup, and one extra space in a claim's cell is a different cell.
-->
<script lang="ts">
	import LineRef from "./LineRef.svelte";
	import type { Claim } from "./answer.ts";

	interface Props {
		term: Claim[];
		/** Which term of the grant this is, from 1. */
		index: number;
		/** How many terms the grant has. With one, the table needs no label. */
		of: number;
		/** The grant's number, for the region's name. */
		number: number;
	}
	let { term, index, of, number }: Props = $props();

	const label = $derived(of > 1 ? `what grant ${number} admits, term ${index} of ${of}` : `what grant ${number} admits`);
</script>

{#if of > 1}<p class="label term-label">term {index} of {of}</p>{/if}
<!-- The table is wider than a narrow pane and scrolls sideways in its own
     box. A scroll box with nothing focusable inside it cannot be scrolled
     without a mouse, so the box itself is a named region the keyboard
     reaches. -->
<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
<div class="table" role="group" tabindex="0" aria-label={label}>
	<table class="terms">
		<thead><tr><th class="label">claim</th><th class="label">admits</th><th class="label">in words · as written</th></tr></thead>
		<tbody>
			{#each term as row (row.claim)}<tr><td>{row.claim}</td><td class="val{row.mark ? ' v-' + row.mark : ''}">{row.rendered}</td><td class="words{row.mark === 'unknown' ? ' v-unknown' : ''}">{row.words}{#if row.note}<sup>{row.note}</sup>{/if}{#each row.written as w (w.line + (w.operator ?? '') + (w.member ?? ''))}<span class="why">{" · "}<LineRef line={w.line} />{" " + (w.operator || w.member || "")}</span>{/each}</td></tr>{/each}
			<tr class="rest"><td>any other claim</td><td class="val">any</td><td class="words">{"unconstrained "}<span class="why">· no condition names it</span></td></tr>
		</tbody>
	</table>
</div>
