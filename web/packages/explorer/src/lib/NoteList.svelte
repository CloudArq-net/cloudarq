<!--
  Caveats and anomalies, numbered so the sentence and the term table can point
  at them, each with every field the engine's types carry. A note the sentence
  refers to links back to the reference, so a reader who followed one down can
  get back up without scrolling.

  Spaces that carry meaning are written as expressions; see TermTable.svelte.
-->
<script lang="ts">
	import type { Note } from "./answer.ts";

	interface Props {
		/** The element-id prefix: `doc` for the document's own anomalies, `g<n>`
		 *  for a grant's. */
		id: string;
		notes: Note[];
		/** The note numbers the sentence refers to, which get the link back. */
		referenced?: Set<number>;
	}
	let { id, notes, referenced = new Set() }: Props = $props();
</script>

<ol class="notes" aria-label="caveats and anomalies">
	{#each notes as note (note.number)}<li id="{id}-n{note.number}"><span class="v-unknown">{note.kind}</span><span class="kind">{" "}{#if note.anomaly}{"· kind "}<code>{note.anomaly}</code>{" "}{/if}{#if note.claim}{"· claim "}<code>{note.claim}</code>{" "}{/if}{#if note.construct}{"· construct "}<code>{note.construct}</code>{" "}{/if}{"· source "}<code>{note.source}</code></span><br />{note.message}{#if referenced.has(note.number)}{" "}<button type="button" class="ref" data-ref="{id}-r{note.number}" aria-label="back to the sentence">↩</button>{/if}</li>{/each}
</ol>
