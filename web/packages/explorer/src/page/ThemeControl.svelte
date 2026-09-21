<!--
  The theme, by the system or by a choice. A choice lasts for this page load
  and no longer: the explorer keeps no storage of any kind, and a control that
  remembered would be the one thing on the page that did.
-->
<script lang="ts">
	const choices = ["system", "light", "dark"] as const;
	type Choice = (typeof choices)[number];

	let chosen = $state<Choice>("system");

	function choose(choice: Choice): void {
		chosen = choice;
		const root = document.documentElement;
		if (choice === "system") delete root.dataset.theme;
		else root.dataset.theme = choice;
	}
</script>

<div class="theme" role="group" aria-label="theme">
	<span class="label">theme</span>
	{#each choices as choice (choice)}<button type="button" data-theme-choice={choice} aria-pressed={chosen === choice} onclick={() => choose(choice)}>{choice}</button>{/each}
</div>
