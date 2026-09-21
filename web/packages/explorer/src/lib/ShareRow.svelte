<!--
  The address bar already holds the state; this row makes it a link. The link
  text is the whole answer — every grant's sentence, or the policy's answer
  for the token — so that a reader of a pull request sees what the page says
  and not its first line.

  While the row is closed none of that is on screen, and a keystroke need not
  spell it.

  Only the explorer that owns the page's address renders this row: `href` is
  the address, and an explorer that does not write one has none to offer.
-->
<script lang="ts">
	import { explorer } from "./context.ts";

	interface Props {
		open: boolean;
		/** The whole address, as a reader would copy it. */
		href: string;
		/** Every grant's sentence, or the policy's answer for the token. */
		answerText: string;
		/** The answer readout, which goes after the link in the markdown. */
		summary: string;
		/** How many characters the fragment carries. */
		fragmentLength: number;
		/** Whether anything is pasted at all. */
		pasted: boolean;
		/** Whether a token is pasted as well as a policy. */
		withToken: boolean;
	}
	let { open, href, answerText, summary, fragmentLength, pasted, withToken }: Props = $props();

	// The row belongs to one explorer, and so does every name in it.
	const { id, landmark } = explorer();

	const markdown = $derived(answerText ? `[${answerText}](${href})${summary ? " — cloudarq admits · " + summary : ""}` : "");
	const note = $derived(
		pasted
			? `${fragmentLength} characters in the fragment: the policy${withToken ? " and the token" : ""}, sent nowhere.${answerText ? ` Markdown: [${answerText}](…)` : ""}`
			: "Nothing to share yet: nothing is pasted.",
	);

	let field = $state<HTMLInputElement | null>(null);
	let urlLabel = $state("copy");
	let markdownLabel = $state("copy as markdown");

	/** focusField selects the whole address, which is one keystroke from a copy
	 *  where the clipboard is not ours to write. */
	export function focusField(): void {
		field?.focus();
		field?.select();
	}

	// The button says what happened. Without clipboard access the field is
	// selected instead, one keystroke from a copy, rather than a button that
	// looks as though it worked.
	function copy(text: string, say: (word: string) => void, idle: string, button: HTMLButtonElement): void {
		const select = () => {
			field?.select();
			say("select all, then copy");
		};
		const restore = () => button.addEventListener("blur", () => say(idle), { once: true });
		if (!navigator.clipboard) {
			select();
			restore();
			return;
		}
		navigator.clipboard.writeText(text).then(
			() => {
				say("copied");
				restore();
			},
			() => {
				select();
				restore();
			},
		);
	}
</script>

<section class="share" id={id("share")} hidden={!open} aria-label={landmark() ? "this analysis, as a link" : undefined}>
	<label class="label" for={id("share-url")}>this analysis, as a link</label>
	<div class="share-row">
		<input bind:this={field} id={id("share-url")} type="text" readonly value={href} spellcheck="false" data-markdown={markdown} />
		<button type="button" id={id("copy-url")} onclick={(e) => copy(href, (w) => (urlLabel = w), "copy", e.currentTarget)}>{urlLabel}</button>
		<button type="button" id={id("copy-md")} onclick={(e) => copy(markdown || href, (w) => (markdownLabel = w), "copy as markdown", e.currentTarget)}>{markdownLabel}</button>
	</div>
	<p class="readout" id={id("share-note")}>{note}</p>
	<p class="prose muted">The fragment holds the policy and the token, deflated and base64url-encoded; a browser never sends a fragment to a server. Markdown puts the answer in the link text, so a pull request shows the sentence before anyone clicks.</p>
</section>
