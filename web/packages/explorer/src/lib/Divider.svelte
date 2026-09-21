<!--
  The divider between the panes: a pointer drag, and arrow keys when focused.
  The split is one custom property on the grid, and its bounds are read from
  the tokens rather than written here, because a length that is not a token is
  a length nobody decided.
-->
<script lang="ts">
	interface Props {
		/** The element whose --split the divider moves. */
		grid: HTMLElement | null;
	}
	let { grid }: Props = $props();

	let element = $state<HTMLDivElement | null>(null);
	let min = $state(0);
	let max = $state(100);
	let split = $state(0);

	$effect(() => {
		if (!grid) return;
		const tokens = getComputedStyle(document.documentElement);
		min = parseFloat(tokens.getPropertyValue("--pane-min"));
		max = parseFloat(tokens.getPropertyValue("--pane-max"));
		split = parseFloat(getComputedStyle(grid).getPropertyValue("--split"));
	});

	function setSplit(v: number): void {
		if (!grid) return;
		split = Math.min(max, Math.max(min, Math.round(v)));
		grid.style.setProperty("--split", String(split));
	}

	function onkeydown(e: KeyboardEvent): void {
		const step = e.shiftKey ? 10 : 2;
		const next = { ArrowLeft: split - step, ArrowRight: split + step, Home: min, End: max }[e.key];
		if (next === undefined) return;
		e.preventDefault();
		setSplit(next);
	}

	function onpointerdown(e: PointerEvent): void {
		if (!element || !grid) return;
		element.setPointerCapture(e.pointerId);
		const box = grid.getBoundingClientRect();
		const move = (ev: PointerEvent) => setSplit(((ev.clientX - box.left) / box.width) * 100);
		element.addEventListener("pointermove", move);
		element.addEventListener("pointerup", () => element?.removeEventListener("pointermove", move), { once: true });
	}
</script>

<!-- A focusable separator is the window-splitter pattern: it carries
     aria-valuemin, aria-valuemax and aria-valuenow and it is moved with the
     arrow keys, so it is interactive by its role's own definition. axe-core
     4.13.0 reports it clean on every state web/page-check.mjs walks. -->
<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<div
	bind:this={element}
	class="divider"
	role="separator"
	aria-orientation="vertical"
	aria-label="resize the panes"
	tabindex="0"
	aria-valuemin={min}
	aria-valuemax={max}
	aria-valuenow={split}
	{onkeydown}
	{onpointerdown}
></div>
