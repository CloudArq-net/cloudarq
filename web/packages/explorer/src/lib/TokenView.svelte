<!--
  The token view: a token this policy rejected, read claim by claim against
  every grant. Only the payload is read and nothing leaves the page, and both
  of those are said on screen rather than assumed.

  The prose is written on one line per paragraph: a line break in markup is a
  space in the text, and this copy is read back character for character
  against the page as it shipped.
-->
<script lang="ts">
	import Spans from "./Spans.svelte";
	import TokenOutcome from "./TokenOutcome.svelte";
	import type { Answer, DocumentReport, Explanation } from "./answer.ts";
	import { explorer } from "./context.ts";

	interface Props {
		token: string;
		/** The policy's answer, which the outcomes are read against. */
		answer: Answer | null;
		/** The engine's answer for the token, or null when there is none. */
		explanation: Explanation | null;
		policyBytes: Uint8Array;
		/** Why the address's fragment could not be read, when it could not. */
		unreadableLink?: string;
		/** The address of each grant's witness in this view, by grant number. */
		witnessHrefs: Record<number, string>;
		/** The address of the admits view. */
		admitsHref: string;
		oninput: (token: string) => void;
		onwitness: (witness: string) => void;
		onadmits: () => void;
	}
	let { token, answer, explanation, policyBytes, unreadableLink = "", witnessHrefs, admitsHref, oninput, onwitness, onadmits }: Props = $props();

	// a region is a landmark only where the explorer is the page
	const { landmark } = explorer();

	const readable = $derived(Boolean(answer) && !answer!.error);
	const doc = $derived(readable ? (answer!.document as DocumentReport) : null);
	const inexact = $derived(readable && answer!.grants.some((g) => !g.exact));
	const witnessed = $derived(readable ? answer!.grants.filter((g) => g.witness) : []);
	const stopped = $derived(Boolean(explanation?.stopped));
	const answered = $derived(Boolean(explanation) && !stopped && !explanation!.token.error && !explanation!.error);

	let box = $state<HTMLTextAreaElement | null>(null);
	// written only when its text is not already the token; see PolicyPane.svelte
	$effect(() => {
		if (box && box.value !== token) box.value = token;
	});
</script>

<div class="answer token-view">
	<label class="token">
		<span class="label">token · the decoded payload, or the whole token</span>
		<textarea bind:this={box} name="token" spellcheck="false" placeholder="Paste a token this policy rejected." oninput={(e) => oninput(e.currentTarget.value)}></textarea>
	</label>
	<p class="prose muted" data-copy="read" hidden={!readable}>Only the payload is read: the signature is not checked here, and nothing leaves this page. Each claim is shown against the constraint each grant puts on it; a claim the policy does not name is listed and ignored.</p>
	<p class="prose muted" data-copy="bound" hidden={!inexact}>A grant that is an upper bound does not prove a token in: a token nothing excludes is not thereby proven admitted.</p>
	<p class="prose" data-copy="witness" hidden={!(readable && !token.trim() && witnessed.length > 0)}>Or start from a grant's witness, the token shown under it in the admits view: <span class="witness-links">{#each witnessed as grant, i (grant.number)}{#if i > 0}{", "}{/if}<a href={witnessHrefs[grant.number] ?? "#"} onclick={(e) => { e.preventDefault(); onwitness(grant.witness ?? ""); }}>grant {grant.number}'s witness</a>{/each}</span>.</p>
	<p class="prose" data-copy="unreadable-link" hidden={!unreadableLink}>The address holds a fragment this page could not read: <span class="reason">{unreadableLink}</span>. Nothing was loaded from it.</p>
	<p class="prose" data-copy="no-policy" hidden={readable}>There is no policy yet. Paste one into the policy pane, or start from an example under <a href={admitsHref} data-view="admits" onclick={(e) => { e.preventDefault(); onadmits(); }}>admits</a>; then each claim of the token is shown against the constraint the policy puts on it, and the first claim that fails names the reason.</p>
	<p class="prose" data-copy="unreadable-token" hidden={!(explanation && !stopped && explanation.token.error)}>The token could not be read: <code class="error">{explanation && !stopped ? (explanation.token.error ?? "") : ""}</code></p>
	<p class="prose" data-copy="stopped" hidden={!stopped}>The engine stopped while reading this token, and was restarted: <code class="error">{stopped ? (explanation!.error ?? "") : ""}</code>. No answer exists for it.</p>
	<div class="outcomes">
		{#if answered && explanation && doc}
			{#if explanation.grants.length >= 2}
				<section class="token-answer" aria-label={landmark() ? "answer for this token from the policy" : undefined}>
					<h3><Spans spans={explanation.heading} /></h3>
					<p class="sentence"><Spans spans={explanation.spans} /></p>
				</section>
			{/if}
			{#each explanation.grants as outcome (outcome.number)}<TokenOutcome {outcome} grant={answer!.grants[outcome.number - 1]} statement={doc.statements[outcome.statement]} {doc} {policyBytes} token={explanation.token} />{/each}
		{/if}
	</div>
</div>
