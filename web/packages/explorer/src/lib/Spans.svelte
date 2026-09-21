<!--
  A sentence's runs: a value in code, coloured by what the engine knows about
  it; a run that refers to a note gets a superscript reference to it, and the
  first reference to each note carries the anchor the note links back to.

  The markup is written without a line break inside the sentence because a
  line break is a space: the sentence's text is the product and an extra
  space in it is a different sentence.
-->
<script lang="ts">
	import type { Span } from "./answer.ts";

	interface Props {
		spans: Span[];
		/** The grant's element-id prefix. Without one the runs carry no note
		 *  references: a heading points at nothing. */
		id?: string;
	}
	let { spans, id = "" }: Props = $props();

	// the first run that refers to a note is the one the note links back to
	const firstFor = $derived(
		spans.map((span, i) => Boolean(span.note) && spans.findIndex((other) => other.note === span.note) === i),
	);
</script>

{#each spans as span, i (i)}{#if span.mark === "code"}<code>{span.text}</code>{:else if span.mark === "exact"}<code class="v-exact">{span.text}</code>{:else if span.mark}<span class="v-{span.mark}">{span.text}</span>{:else}{span.text}{/if}{#if span.note && id}<sup><button type="button" class="ref" id={firstFor[i] ? `${id}-r${span.note}` : undefined} data-ref="{id}-n{span.note}">{span.note}</button></sup>{/if}{/each}
