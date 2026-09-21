# @cloudarq/explorer

The CloudArq trust-policy explorer as a Svelte 5 component: paste a role's
trust policy, read who it admits, and read a token against every grant. The
engine is `internal/report` compiled to WebAssembly; the component renders what
the engine answers and evaluates nothing of its own.

Nothing leaves the page and nothing is stored. The whole analysis is in the URL
fragment, so a link reproduces it exactly.

## Install

```
npm install @cloudarq/explorer svelte
```

`svelte` is a peer dependency: one copy of the runtime on the page.

## Use

The component does not fetch the engine and names no URL for it. The host
compiles the bytes it serves and hands the engine over, so `connect-src 'self'`
stays literally true on whichever origin serves them, and two explorers on one
page share one instance rather than each starting a heap of their own.

```svelte
<script lang="ts">
  import { Explorer, compileEngine, engineFor, type Engine } from "@cloudarq/explorer";

  let engine = $state<Engine | null>(null);
  let engineError = $state("");

  $effect(() => {
    let live = true;
    void compileEngine(new URL("cloudarq.wasm", document.baseURI))
      .then((module) => engineFor(module))
      .then(
        (loaded) => { if (live) engine = loaded; },
        (err: Error) => { if (live) engineError = err.message; },
      );
    return () => { live = false; };
  });
</script>

<Explorer {engine} {engineError} />
```

That is an embedded explorer: it renders a plain element, adds no landmark to
the page around it, leaves `location.hash` alone, and opens with the document
every explorer opens with. A page that *is* the explorer says so:

```svelte
<Explorer {engine} {engineError} ownsAddress landmark />
```

`ownsAddress` makes the explorer a function of `location.hash`; `landmark`
makes it the page's `<main>` and names its panes as regions. At most one
explorer on a page may have either: two that wrote the address would fight
over it, and two main landmarks are two answers to where the page begins.
Everything else is safe to mount twice, because every element id is spelt
under the instance that rendered it.

The two stylesheets are `<link>`ed by the host page, not imported by the
component, so the page carries no inline style:

```html
<link rel="stylesheet" href="/tokens.css">
<link rel="stylesheet" href="/explorer.css">
```

They are at `@cloudarq/explorer/tokens.css` and
`@cloudarq/explorer/explorer.css` for a build that copies them, and the engine
is at `@cloudarq/explorer/cloudarq.wasm` (`dist/cloudarq.wasm` inside the
package): copy it onto your own origin at build time and serve it beside the
page.

### Props

| Prop | Default | What it is |
|---|---|---|
| `engine` | — | The engine, or `null` while it is still being compiled. |
| `engineError` | `""` | What to say when the engine did not arrive. |
| `ownsAddress` | `false` | Whether this explorer reads and writes `location.hash`. At most one explorer on a page may. |
| `landmark` | `false` | Whether this explorer is the page's `<main>`, with its panes as named regions, rather than a plain element. At most one explorer on a page may. |
| `shareOpen` | `false` | Bindable. Whether the share row is open; the host's own bar carries the control that opens it. Only an explorer with `ownsAddress` renders the row — the row offers the address as a link, and an explorer that does not write one has none to offer. |

`focusShareField()` is exported for the host's bar to call when it opens the
row, and `shareId` names the row it opens, for the bar's `aria-controls`. On an
explorer without `ownsAddress` there is no row: `shareId` is empty and
`focusShareField()` does nothing.

## The fragment

```
#v1.<dialect>.<policy>.<token>.<view>
```

`policy` and `token` are the pasted bytes, raw-deflated and base64url-encoded
without padding; either may be empty. `view` is `admits` or `token`; `admits` is
the default and is omitted, as is a trailing empty field. `#v1.aws` is the empty
state. A fragment of another version is refused by name rather than read as
something else.

The grammar is a published surface: links written by this page are in pull
requests and in issues. Changing any of it is a breaking change.

## Licence

Apache-2.0. The vendored `wasm_exec.js` is TinyGo's, BSD-3-Clause, copied
verbatim with its version and digest recorded in its first line.
