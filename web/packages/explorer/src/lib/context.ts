// What a piece of this explorer's markup needs to know about the explorer it
// is part of: its name, and whether it is the page.
//
// Both are facts about the instance rather than about the document, and both
// are needed nine levels down — a line reference inside a claim table inside
// a grant — so they travel on the context rather than through a prop on
// every component in between.
//
// The name is what keeps two explorers on one page apart. An id names one
// element in the whole document, and this component renders thirteen of them
// plus one per line of the pasted document and one per note; two mounts
// would spell every one of those names twice, so a label would name the
// other explorer's field and a reference would scroll the other explorer's
// line into view. The prefix comes from $props.id(), which is unique per
// component instance and survives a consumer's server render.
//
// Whether the explorer is the page decides what is a landmark. A pane named
// "policy" is a region worth navigating to when the explorer is the page; in
// someone else's page it is a second landmark with a name the page's own
// landmarks do not know about, and two embedded explorers are two of each.
import { getContext, setContext } from "svelte";

const KEY = Symbol("cloudarq.explorer");

/** The explorer a piece of markup is part of. */
export interface Rendering {
	/** Spells one of this explorer's element ids. */
	id: (name: string) => string;
	/** Whether this explorer's regions are landmarks of the page. */
	landmark: () => boolean;
}

/** provideExplorer names the explorer that is rendering, for every component
 *  under it. It answers with the same object, because the explorer spells
 *  ids of its own. */
export function provideExplorer(uid: string, landmark: () => boolean): Rendering {
	const rendering: Rendering = { id: (name) => `${uid}-${name}`, landmark };
	setContext(KEY, rendering);
	return rendering;
}

/** explorer answers with the explorer this component is rendering inside. */
export function explorer(): Rendering {
	const rendering = getContext<Rendering | undefined>(KEY);
	if (!rendering) throw new Error("this component is part of an explorer's markup and is not inside an Explorer, so the id it would write belongs to no instance");
	return rendering;
}
