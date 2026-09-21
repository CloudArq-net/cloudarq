<!--
  A reference to one line of the document. It is a button and not a link
  because it marks a line in the policy pane rather than changing the address:
  where a reader is looking is not the analysis.
-->
<script lang="ts">
	import { explorer } from "./context.ts";

	interface Props {
		line: number;
	}
	let { line }: Props = $props();

	// The line it marks is a line of this explorer's listing; on a page with
	// two explorers the other one's listing has a line of the same number.
	const { id } = explorer();
</script>

<button type="button" class="ref" data-ref={id(`L${line}`)}>L{line}</button>
