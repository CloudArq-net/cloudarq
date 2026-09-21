<!--
  What the page is, the corpus documents, and how to read an answer under a
  closed disclosure. It is the foot of the answer pane in every state, not a
  state of its own: the three documents are the way in, and the disclosure is
  what the colours mean, which is owed to a reader looking at their own policy
  for the first time as much as to an empty page.

  The prose is written on one line per paragraph. A line break in markup is a
  space in the text, and this copy is read back character for character by
  web/text-diff.mjs against the page as it shipped.
-->
<script lang="ts">
	import { examples } from "./examples.ts";

	interface Props {
		/** Why the address's fragment could not be read, when it could not. */
		unreadableLink?: string;
		/** Whether the engine has an answer on screen; with none, the block says
		 *  there is nothing to evaluate yet. */
		answered?: boolean;
		/** The address of each example, by corpus name; "#" until the document
		 *  has been deflated. */
		hrefs: Record<string, string>;
		/** Follow an example without a document load. */
		onexample: (name: string) => void;
	}
	let { unreadableLink = "", answered = false, hrefs, onexample }: Props = $props();
</script>

<div class="answer teach prose">
	<p data-copy="unreadable-link" hidden={!unreadableLink}>The address holds a fragment this page could not read: <span class="reason">{unreadableLink}</span>. Nothing was loaded from it.</p>
	<p data-copy="nothing" hidden={answered}>Nothing to evaluate yet. Paste a trust policy into the policy pane, or start from one of the corpus documents below.</p>
	<h3 class="label">examples from the conformance corpus</h3>
	<ul>
		{#each examples as example (example.name)}<li><a href={hrefs[example.name] ?? "#"} data-example={example.name} onclick={(e) => { e.preventDefault(); onexample(example.name); }}>{example.name}</a><span>{#each example.gloss as run, i (i)}{#if run.code}<code>{run.text}</code>{:else}{run.text}{/if}{/each}</span></li>{/each}
	</ul>
	<details class="how">
		<summary>how to read this</summary>
		<p>The answer is one sentence per grant, saying who the policy admits; then each claim with the values it admits, in words and as written in the document; then a decoded token the grant accepts; then the statement's own bytes. A value is coloured by what the engine knows about it: <span class="v-exact">exact</span>, <span class="v-beyond">admitted beyond the tenant the policy names</span>, or <span class="v-unknown">unknown, because a construct could not be evaluated</span>. Unknown is never folded into a clean answer.</p>
		<p>Everything runs in this page. Nothing is sent anywhere, and the address bar holds the whole analysis: copy the link and the reader sees exactly this.</p>
		<h4 class="label">keyboard</h4>
		<p><kbd>Tab</kbd> moves between the policy, the divider and the answer. On the divider, <kbd>←</kbd> and <kbd>→</kbd> resize by 2%, with <kbd>Shift</kbd> by 10%; <kbd>Home</kbd> and <kbd>End</kbd> go to the limits. <kbd>Enter</kbd> on a statement mark such as <kbd>[0]</kbd>, or on <kbd>statement[0]</kbd> in a grant's head, selects the statement and its grants in both panes. <kbd>Enter</kbd> on a line reference such as <kbd>L13</kbd> marks that line in the policy.</p>
	</details>
</div>
