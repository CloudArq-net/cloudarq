<!--
  Evidence: the document, the statement's bytes located and digested, the
  grant's own facts, and the statement's bytes quoted from the source. Open
  when the answer is a bound, because a reader told the set is a bound is owed
  the bytes without a click.

  The summary is always current; the body is written only while the disclosure
  is open. A keystroke moves every byte offset in the document, and rewriting
  fifty closed bodies costs the frame the answer is supposed to land in. What
  a reader cannot see does not have to be right yet — but what they can see
  does, so opening a stale body writes it first.

  Spaces that carry meaning are written as expressions; see TermTable.svelte.
-->
<script lang="ts">
	import type { DocumentReport, Statement } from "./answer.ts";
	import type { Snippet } from "svelte";

	interface Props {
		/** The statement this evidence is for, as the engine located it. */
		statement: Statement;
		/** The document the statement was located in. */
		doc: DocumentReport;
		/** The pasted document as bytes; the engine's offsets index these. */
		policyBytes: Uint8Array;
		/** Whether the grant's set is exact. A bound opens the evidence. */
		exact: boolean;
		/** The grant's own facts, as <dt>/<dd> pairs. */
		extra?: Snippet;
		/** Write the body even while the disclosure is closed. The admits view
		 *  leaves it false: a keystroke moves every offset in the document and
		 *  fifty closed bodies are fifty rewrites nobody can see. The token view
		 *  sets it, because there is one outcome per grant and the whole view is
		 *  rebuilt on every keystroke anyway, so deferring saves nothing and a
		 *  reader who opens it would read the document as it was. */
		writeWhileClosed?: boolean;
	}
	let { statement, doc, policyBytes, exact, extra, writeWhileClosed = false }: Props = $props();

	interface Located {
		doc: DocumentReport;
		statement: Statement;
		policyBytes: Uint8Array;
	}

	// The disclosure opens for a bound and stays wherever the reader puts it
	// afterwards, so this reads the prop once on purpose.
	// svelte-ignore state_referenced_locally
	let open = $state(!exact);
	let located = $state.raw<Located | null>(null);
	$effect(() => {
		const now: Located = { doc, statement, policyBytes };
		if (open || writeWhileClosed) located = now;
	});

	const decoder = new TextDecoder();
	const summary = $derived(
		`evidence · statement[${statement.index}] · ${statement.length} bytes at offset ${statement.offset} · sha256 ${statement.sha256.slice(0, 8)}…` +
			(exact ? "" : " · open because the set is an upper bound"),
	);
	// the statement's own bytes, cut from the pasted text at the byte offsets
	// the engine reported and never re-serialised
	const quoted = $derived(
		located ? decoder.decode(located.policyBytes.subarray(located.statement.offset, located.statement.offset + located.statement.length)) : "",
	);
</script>

<details class="evidence" bind:open>
	<summary>{summary}</summary>
	<dl class="pairs">
		<dt>document</dt><dd>{#if located}{located.doc.bytes + " bytes as pasted, " + located.doc.lines + " lines · sha256 "}<span class="digest">{located.doc.sha256}</span>{/if}</dd>
		<dt>statement</dt><dd>{#if located}{"[" + located.statement.index + "], bytes " + located.statement.offset + "–" + (located.statement.offset + located.statement.length - 1) + ", lines " + located.statement.firstLine + "–" + located.statement.lastLine + " · sha256 "}<span class="digest">{located.statement.sha256}</span>{" · quoted below verbatim, never re-serialised"}{/if}</dd>
		{@render extra?.()}
	</dl>
	<pre class="quote">{quoted}</pre>
</details>
