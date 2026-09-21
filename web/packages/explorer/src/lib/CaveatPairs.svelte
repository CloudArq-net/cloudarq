<!--
  The caveats of a grant, as evidence rows: what could not be evaluated, where
  the engine read it, and the note that spells it out. A grant with none says
  so in the admits view, where "exact" is a claim the evidence has to carry;
  in the token view the row is dropped, because the sentence there is about
  the token and an empty row would be noise.

  Spaces that carry meaning are written as expressions; see TermTable.svelte.
-->
<script lang="ts">
	import type { Note } from "./answer.ts";

	interface Props {
		notes: Note[];
		/** Whether to say so when there is no caveat. */
		showNone?: boolean;
	}
	let { notes, showNone = true }: Props = $props();

	const caveats = $derived(notes.filter((n) => n.kind === "caveat"));
</script>

{#if caveats.length === 0}{#if showNone}<dt>caveats</dt><dd>none: the set is exact</dd>{/if}{:else}{#each caveats as note (note.number)}<dt><span class="v-unknown">caveat</span></dt><dd>{#if note.claim}{"claim "}<code>{note.claim}</code>{" · "}{/if}{note.message}{" · source "}<code>{note.source}</code>{` (note ${note.number})`}</dd>{/each}{/if}
