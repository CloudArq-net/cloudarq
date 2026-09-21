<!--
  The answer pane: one article per grant, or the token against every grant.
  The teaching block is the foot of the pane in every state and is rendered
  outside the state's branch, so a reader who opened "how to read this" and
  then typed does not have it closed under them.

  The prose is written on one line per paragraph: a line break in markup is a
  space in the text.
-->
<script lang="ts">
	import GrantArticle from "./GrantArticle.svelte";
	import NoteList from "./NoteList.svelte";
	import Teach from "./Teach.svelte";
	import TokenView from "./TokenView.svelte";
	import type { Answer, DocumentReport, Explanation, Grant } from "./answer.ts";
	import type { View } from "./fragment.ts";
	import { explorer } from "./context.ts";

	interface Props {
		view: View;
		answer: Answer | null;
		/** The answer's grants, each keeping the object it had while it reads the
		 *  same, so an article nothing changed is left alone. */
		grants: Grant[];
		explanation: Explanation | null;
		token: string;
		policyBytes: Uint8Array;
		selected: Set<number>;
		unreadableLink: string;
		/** The readout, already in the two parts it is drawn in. */
		readout: { head: string; rest: string; mark: string };
		/** The address of each view, of each example and of each witness. */
		viewHrefs: Record<string, string>;
		exampleHrefs: Record<string, string>;
		witnessHrefs: Record<number, string>;
		onview: (view: View) => void;
		onexample: (name: string) => void;
		onwitness: (witness: string) => void;
		ontoken: (token: string) => void;
	}
	let { view, answer, grants, explanation, token, policyBytes, selected, unreadableLink, readout, viewHrefs, exampleHrefs, witnessHrefs, onview, onexample, onwitness, ontoken }: Props = $props();

	// the document's own notes are named under this explorer, as a grant's are
	const { id, landmark } = explorer();
	const readable = $derived(Boolean(answer) && !answer!.error);
	const doc = $derived(readable ? (answer!.document as DocumentReport) : null);
	const anomalies = $derived(doc?.anomalies ?? []);
</script>

<section class="pane" id={id("answer-pane")} aria-label={landmark() ? "answer" : undefined}>
	<div class="pane-head">
		<svelte:element this={landmark() ? "nav" : "div"} class="views" aria-label={landmark() ? "answer view" : undefined}><a href={viewHrefs.admits ?? "#"} data-view="admits" aria-current={view === "admits" ? "page" : undefined} onclick={(e) => { e.preventDefault(); onview("admits"); }}>admits</a><a href={viewHrefs.token ?? "#"} data-view="token" aria-current={view === "token" ? "page" : undefined} onclick={(e) => { e.preventDefault(); onview("token"); }}>token</a></svelte:element>
		<span class="readout" id={id("answer-readout")} aria-live="polite">{readout.head}{#if readout.rest}<span class={readout.mark}>{readout.rest}</span>{/if}</span>
	</div>
	<div class="pane-body" id={id("answer-body")}>
		{#if view === "token"}
			<TokenView {token} {answer} {explanation} {policyBytes} {unreadableLink} {witnessHrefs} admitsHref={viewHrefs.admits ?? "#"} oninput={ontoken} {onwitness} onadmits={() => onview("admits")} />
		{:else if answer && answer.error}
			{#if answer.stopped}
				<div class="answer">
					<p class="sentence">The engine stopped while reading this document, and was restarted.</p>
					<p class="prose"><code class="error">{answer.error}</code></p>
					<p class="prose muted">No answer exists for what is in the policy pane: the engine gave none before it stopped, and the previous answer was for another document. Every document the engine reads it answers, so this is a defect in the engine, not in the document.</p>
				</div>
			{:else}
				<div class="answer">
					<p class="sentence">This is not a trust policy the engine can read.</p>
					<p class="prose"><code class="error">{answer.error}</code></p>
					<p class="prose muted">The engine reads exactly one JSON object; what it refuses, it names. Everything it can read at all becomes an answer, with what it could not evaluate declared.</p>
				</div>
			{/if}
		{:else if answer && doc}
			{#if anomalies.length}
				<div class="answer">
					<h3 class="grant-head"><span>document</span><span class="v-unknown">{anomalies.length} {anomalies.length === 1 ? "anomaly" : "anomalies"}</span></h3>
					<NoteList id={id("doc")} notes={anomalies} />
				</div>
			{/if}
			{#each grants as grant (grant.number)}<GrantArticle {grant} statement={doc.statements[grant.statement]} {doc} {policyBytes} selected={selected.has(grant.statement)} witnessHref={witnessHrefs[grant.number] ?? "#"} {onwitness} />{/each}
		{/if}
		{#if readable}<p class="bridge prose">One policy, here. <code>cloudarq admits</code> will run the same engine over every role in an account; today it prints a usage line. The engine is public: <a href="https://github.com/CloudArq-net/cloudarq">github.com/CloudArq-net/cloudarq</a></p>{/if}
		<Teach {unreadableLink} answered={Boolean(answer)} hrefs={exampleHrefs} {onexample} />
	</div>
</section>
