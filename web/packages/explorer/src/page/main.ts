// The standalone page mounts the explorer.
//
// The page paints before the engine arrives: the bar, both pane heads and
// the readout that says the engine is still loading are on screen while the
// 380 KB of WebAssembly is fetched and compiled. A page that waited would
// show nothing at all for the whole of that, which is the fold row and the
// first paint both.
import { mount } from "svelte";

import Page from "./Page.svelte";

// Into the body, not into a wrapper of its own: the panes size themselves
// against the flex column the stylesheet makes of <body>, and a <div> between
// the two is a flex item that is not a flex container, which leaves the page
// scrolling as a whole where the shipped page scrolls each pane.
mount(Page, { target: document.body });
