<!--
  The standalone page: the bar, and the explorer under it. The bar is the
  page's and not the component's — a host that mounts the explorer in a
  landing has a bar of its own — so it lives here, and the one thing it needs
  from the explorer is the control that opens the share row.
-->
<script lang="ts">
	import { flushSync } from "svelte";

	import { compileEngine, engineFor, Explorer } from "../lib/index.ts";
	import type { Engine } from "../lib/index.ts";
	import ThemeControl from "./ThemeControl.svelte";

	// The engine's URL is the page's, not the component's: the component never
	// names one, so connect-src 'self' is literally true wherever the page is
	// served. It is resolved against the document because the bundle sits under
	// assets/ and the engine sits beside the page.
	let engine = $state<Engine | null>(null);
	let engineError = $state("");
	$effect(() => {
		let live = true;
		void compileEngine(new URL("cloudarq.wasm", document.baseURI))
			.then((module) => engineFor(module))
			.then(
				(loaded) => {
					if (live) engine = loaded;
				},
				(err: Error) => {
					if (live) engineError = err.message;
				},
			);
		return () => {
			live = false;
		};
	});

	let shareOpen = $state(false);
	// The bar's control opens a row the explorer renders, so the bar has to be
	// able to name it: the id belongs to the instance, not to the document.
	let explorer = $state<{ focusShareField: () => void; shareId: string } | null>(null);

	function toggleShare(): void {
		shareOpen = !shareOpen;
		if (!shareOpen) return;
		flushSync();
		explorer?.focusShareField();
	}
</script>

<header class="bar">
	<h1 class="name"><b>cloudarq</b> admits <span>· who a trust policy lets in</span></h1>
	<div class="bar-actions">
		<button type="button" id="share-toggle" aria-expanded={shareOpen} aria-controls={explorer?.shareId} onclick={toggleShare}>link</button>
		<ThemeControl />
	</div>
</header>

<!-- This page is the explorer: it is the page's main content and the address
     is its to read and to write. A host that mounts the explorer inside a page
     of its own passes neither, and gets an explorer that touches no landmark
     and no address. -->
<Explorer bind:this={explorer} {engine} {engineError} ownsAddress landmark bind:shareOpen />
