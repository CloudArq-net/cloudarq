#!/usr/bin/env bash
# Builds the explorer into web/dist and proves the build.
#
# The page in web/dist is @cloudarq/explorer's standalone page, built by Vite
# out of the package: there is one explorer in this repository and one page
# that mounts it. What is proven here, in order: the engine compiled to
# WebAssembly, its sizes against the budget, the differential against the
# native engine over every document in the corpus and the generated shapes,
# the entry's refusal of depth, the heap's ceiling, the glue's recovery from a
# trap, the engine's own time in node, the package's type check and tests, the
# package's own rules and byte budget, the rendering differential that holds
# the page to web/text-fixture.json word for word, the tarball a consumer
# installs, the page's behaviour in Chrome under the headers it will be hosted
# with, a host page built from that tarball with the component mounted twice —
# which is the only place the ids, the landmarks, the address's one owner and
# the unmounting can be read — and the page's re-evaluation time in Chrome.
#
# web/text-fixture.json is the record of what the shipped page rendered,
# captured in Chrome before the component existed. It is committed, so the
# differential needs no second page alive to compare against.
#
# Standalone until the Makefile gains web targets. Every step prints what it
# measured; a step that cannot run fails the build rather than printing a
# pass.
#
#   WORK=<dir> web/build.sh     keeps the intermediate files under <dir>
set -euo pipefail
cd "$(dirname "$0")/.."

budget_gzip=400000            # bytes: 400 KB gzipped, product/CONTEXT.md
dist=web/dist
work=${WORK:-$(mktemp -d)}
mkdir -p "$dist" "$work"

echo "── vet ──"
go vet ./web/...
GOOS=js GOARCH=wasm go vet ./web/wasm
echo "vet: web/... and the js/wasm entry are clean"

echo
echo "── build ──"
# web/wasm/target.json is TinyGo's wasm target with a 1 MB linear-memory
# stack in place of the toolchain's 64 KB: the readers recurse once per
# nesting level, the entry refuses a document at 1000 levels and a token at
# 500 (internal/report/nesting.go states the trap depths those sit under),
# and the small stack overflowed at 125. The second build, on the stock
# target, is the fixture that proves the glue recovers from a trap; it is
# not shipped.
#
# -opt=s and wasm-opt -Os rather than z. The keystroke is the budget the
# page is held to and the engine's call is the largest single item in that
# frame, so the size z would save is not bought with the time it costs; the
# step below measures both on every build, so the decision can be reversed
# the day the budget, rather than the frame, is the tight one.
tinygo build -o "$work/engine.wasm" -target web/wasm/target.json -buildmode=c-shared -scheduler=none -opt=s -no-debug ./web/wasm
tinygo build -o "$work/trapping.wasm" -target wasm -buildmode=c-shared -scheduler=none -opt=s -no-debug ./web/wasm
# The engine is built under $work rather than into $dist, because the page's
# own build empties $dist: the engine and the hosted headers are the host's,
# not the bundler's, and they are copied in after Vite has written the page.
wasm-opt -Os --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext \
  --enable-mutable-globals --enable-reference-types --enable-multivalue \
  "$work/engine.wasm" -o "$work/cloudarq.wasm"
go build -o "$work/native" ./web/wasm/native
echo "built $work/cloudarq.wasm; the page it goes beside is built further down, out of the package"

echo
echo "── the harness's own rules ──"
# "secure" is a permitted adjective and "security" a forbidden noun. The
# hosted headers and the browser API that reports their refusals carry the
# word as a name of the platform, which is not the product speaking. The
# package's source is read by web/package-check.mjs; what is read here is the
# harness beside it. build.sh and package-check.mjs are not in the list
# because they carry the pattern: a scanner that scans itself reports its own
# rule and nothing else.
node --input-type=module -e '
import { readFileSync } from "node:fs";
const platform = /Content-Security-Policy|Strict-Transport-Security|securitypolicyviolation|source === "security"/;
const paths = ["_headers", "page-check.mjs", "page-timing.mjs", "diff.mjs", "text-diff.mjs", "chrome.mjs", "chrome.test.mjs", "consumer-check.mjs"];
// read with comments stripped, because a comment declares nothing: what is
// being looked for is the word reaching a reader, and these files say it
// about themselves
const strip = text => text.replace(/\/\*[^]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
const lines = paths.flatMap(path => strip(readFileSync(`web/${path}`, "utf8")).split("\n").map((text, i) => [`${path}:${i + 1}`, text]));
const hits = lines.filter(([, text]) => /secur/i.test(text)).filter(([, text]) => !platform.test(text));
if (hits.length) {
  console.error(`FAIL: the harness says the forbidden noun\n  ${hits.map(([at, text]) => `${at}: ${text.trim()}`).join("\n  ")}`);
  process.exit(1);
}
if (lines.length === 0) { console.error("FAIL: not one line was read out of the harness, so nothing was examined"); process.exit(1); }
console.log(`  clean nothing but the platform says it: ${lines.length} lines over ${paths.length} files`);
'
# What the harnesses' own wait does when a navigation never arrives and when
# it runs out. It drives a Chrome against a server that answers awkwardly on
# purpose, so it is here rather than in CI.
node --test web/chrome.test.mjs

echo
echo "── size ──"
raw=$(stat -f %z "$work/cloudarq.wasm" 2>/dev/null || stat -c %s "$work/cloudarq.wasm")
gz=$(gzip -9 -c "$work/cloudarq.wasm" | wc -c | tr -d ' ')
br=$(brotli -q 11 -c "$work/cloudarq.wasm" | wc -c | tr -d ' ')
before=$(stat -f %z "$work/engine.wasm" 2>/dev/null || stat -c %s "$work/engine.wasm")
echo "tinygo:   $before bytes raw"
echo "wasm-opt: $raw bytes raw, $gz bytes gzip -9, $br bytes brotli -q 11"
if [ "$gz" -gt "$budget_gzip" ]; then
  echo "FAIL: $gz bytes gzipped exceeds the budget of $budget_gzip"
  exit 1
fi
echo "size: $gz bytes gzipped is within the budget of $budget_gzip"

echo
echo "── differential, memory, engine timing, recovery ──"
if ! differential=$(node web/diff.mjs "$work/cloudarq.wasm" "$work/native" "$work" "$work/trapping.wasm" 2>&1); then
  echo "$differential"
  exit 1
fi
echo "$differential"
# where the heap settled is part of this step's output; a step that printed
# nothing about it did not reach it
if ! printf %s "$differential" | grep -qF -- "at or under the"; then
  echo "FAIL: the differential did not report where the largest document settled"
  exit 1
fi

echo
echo "── what -opt=z would cost ──"
# Not spent, and measured rather than remembered: the same engine built for
# size, its gzipped size against the budget and its time against the frame.
tinygo build -o "$work/engine-z.wasm" -target web/wasm/target.json -buildmode=c-shared -scheduler=none -opt=z -no-debug ./web/wasm
wasm-opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext \
  --enable-mutable-globals --enable-reference-types --enable-multivalue \
  "$work/engine-z.wasm" -o "$work/cloudarq-z.wasm"
gz_z=$(gzip -9 -c "$work/cloudarq-z.wasm" | wc -c | tr -d ' ')
shipped="$work/cloudarq.wasm" for_size="$work/cloudarq-z.wasm" fifty="$work/fifty-statements.json" \
gz_shipped="$gz" gz_for_size="$gz_z" budget="$budget_gzip" node --input-type=module -e '
import { readFileSync } from "node:fs";
const { loadEngine } = await import("./web/packages/explorer/src/lib/engine.ts");
const { shipped, for_size, fifty: fiftyPath, gz_shipped, gz_for_size, budget } = process.env;
const fifty = readFileSync(fiftyPath, "utf8");
const medianMs = async path => {
  const engine = await loadEngine(await WebAssembly.compile(readFileSync(path)));
  for (let i = 0; i < 20; i++) engine.admits(fifty);
  const runs = [];
  for (let i = 0; i < 50; i++) { const t = performance.now(); engine.admits(fifty); runs.push(performance.now() - t); }
  return runs.sort((a, b) => a - b)[25];
};
const s = await medianMs(shipped);
const z = await medianMs(for_size);
console.log(`-opt=s, shipped:     ${gz_shipped} bytes gzipped, admits on 50 statements in node: median ${s.toFixed(2)} ms`);
console.log(`-opt=z, not shipped: ${gz_for_size} bytes gzipped, median ${z.toFixed(2)} ms`);
console.log(`the trade: ${gz_shipped - gz_for_size} bytes saved for ${(z - s).toFixed(2)} ms added to the engine call inside every keystroke, against ${budget - gz_shipped} bytes of headroom in the ${budget} byte budget`);
'

echo
echo "── the explorer package and the page it builds ──"
# The page in $dist is this package's. `npm run build` packages the library
# and then builds the page, which empties $dist first — so the engine and the
# hosted headers go in afterwards. _headers is what Cloudflare Pages reads
# from the root of what it serves; it is kept in web/ so that a clean build
# writes it rather than inheriting it.
if [ ! -d node_modules ]; then
  echo "FAIL: node_modules is not installed; run npm ci --ignore-scripts"
  exit 1
fi
npm run check --workspace @cloudarq/explorer
CLOUDARQ_WASM="$work/cloudarq.wasm" CLOUDARQ_TRAPPING_WASM="$work/trapping.wasm" npm test --workspace @cloudarq/explorer
npm run build --workspace @cloudarq/explorer
cp "$work/cloudarq.wasm" web/packages/explorer/dist/
cp "$work/cloudarq.wasm" web/_headers "$dist/"
echo "the package built into web/packages/explorer/dist and the standalone page into $dist, with the engine and the hosted headers beside it"

echo
echo "── the package's own rules ──"
node web/package-check.mjs

echo
echo "── the rendering differential ──"
# Every corpus document through the page, compared word for word against what
# the shipped page rendered. web/text-fixture.json was read out of that page
# in Chrome before the component existed and is committed, so this needs no
# second page alive: the same sentences, the same claim tables, the same
# caveats, the same witnesses and the same readouts.
node web/text-diff.mjs compare "$dist" web/text-fixture.json

echo
echo "── the tarball ──"
# What a consumer installs: built by this gate, packed here, and named by its
# digest. npm pack is byte-reproducible for a given tree, so the digest below
# identifies the bytes rather than the moment they were made.
tarball=$(cd web/packages/explorer && npm pack --ignore-scripts --pack-destination "$work" --silent | tail -1)
tarball_sha=$(shasum -a 256 "$work/$tarball" | cut -d" " -f1)
tarball_bytes=$(stat -f %z "$work/$tarball" 2>/dev/null || stat -c %s "$work/$tarball")
echo "tarball: $tarball, $tarball_bytes bytes, sha256 $tarball_sha"

echo
echo "── axe-core ──"
# A build-machine tool, the same class as TinyGo, Binaryen, brotli, node and
# Chrome: fetched here at a pinned version with its digest checked, injected
# into the page by the debugger, never linked from the page and never
# shipped. A fetch that fails fails the build, because an audit that did not
# run is not an audit that passed.
axe_version=4.13.0
axe_sha256=096912f6e77b4b695fc9304b7be65091db42d98de054da674ae222a11cb33f70
if ! (cd "$work" && npm pack --silent "axe-core@$axe_version" >/dev/null); then
  echo "FAIL: axe-core $axe_version could not be fetched by npm; the accessibility audit is a gate and cannot be skipped"
  exit 1
fi
axe_tarball="$work/axe-core-$axe_version.tgz"
axe_got=$(shasum -a 256 "$axe_tarball" | cut -d" " -f1)
if [ "$axe_got" != "$axe_sha256" ]; then
  echo "FAIL: axe-core $axe_version came back with sha256 $axe_got, not the pinned $axe_sha256"
  exit 1
fi
tar -xzOf "$axe_tarball" package/axe.min.js > "$work/axe.min.js"
axe_bytes=$(stat -f %z "$work/axe.min.js" 2>/dev/null || stat -c %s "$work/axe.min.js")
echo "axe-core: $axe_version, tarball sha256 $axe_got, axe.min.js $axe_bytes bytes; MPL-2.0, build machine only, not in $dist"

echo
echo "── the pages emulator ──"
# The second build-machine tool of the same class as axe: Cloudflare's own
# Pages server, which is what decides what web/dist/_headers means. Pinned
# and its published tarball digested here; npx resolves that same version and
# its dependency tree from the registry, so what this digest pins is the
# version'"'"'s identity, not every byte that runs.
wrangler_version=4.135.0
wrangler_sha256=4903b32fe43dc9d3de0deb3232d93275b993091e174a42ed0489fa157ac64306
if ! (cd "$work" && npm pack --silent "wrangler@$wrangler_version" >/dev/null); then
  echo "FAIL: wrangler $wrangler_version could not be fetched by npm; the hosted headers are a gate and cannot be skipped"
  exit 1
fi
wrangler_got=$(shasum -a 256 "$work/wrangler-$wrangler_version.tgz" | cut -d" " -f1)
if [ "$wrangler_got" != "$wrangler_sha256" ]; then
  echo "FAIL: wrangler $wrangler_version came back with sha256 $wrangler_got, not the pinned $wrangler_sha256"
  exit 1
fi
echo "wrangler: $wrangler_version, tarball sha256 $wrangler_got; MIT OR Apache-2.0, build machine only, not in $dist"

echo
echo "── page check, the page in $dist ──"
node web/page-check.mjs "$dist" "$work/axe.min.js" "npx --yes wrangler@$wrangler_version" --tokens web/packages/explorer/src/lib/tokens.css

echo
echo "── page check, the same page over a URL ──"
# The other half of the harness's one argument: a server somebody else is
# already running. It is the path unit 2b points at a real origin, and a path
# nothing exercises is a path that has never run. The emulator is started here
# rather than by the harness, because over a URL the server under test is the
# one already answering.
# The command is a launcher that starts a wrangler that starts a workerd, so
# stopping it means stopping the tree and not the launcher: a signal to the
# launcher alone leaves a server holding the port.
pages_port=8799
# Both lines end in `|| true` because both are allowed to find nothing: under
# `set -e` a pkill that matched no process is a build that stops here without
# saying why, which is what it did.
stop_pages_dev() {
  [ -n "${pages_dev:-}" ] && kill "$pages_dev" 2>/dev/null || true
  pkill -f "pages dev $dist --ip 127.0.0.1 --port $pages_port" 2>/dev/null || true
}
npx --yes "wrangler@$wrangler_version" pages dev "$dist" --ip 127.0.0.1 --port "$pages_port" --compatibility-date=2025-10-01 >"$work/pages-dev.log" 2>&1 &
pages_dev=$!
# off the shell's job table, so that stopping it is not reported as a failure
# in the middle of the gate's output
disown "$pages_dev" 2>/dev/null || true
trap stop_pages_dev EXIT
for _ in $(seq 1 120); do
  curl -fsS -o /dev/null "http://127.0.0.1:$pages_port/" 2>/dev/null && break
  sleep 1
done
if ! curl -fsS -o /dev/null "http://127.0.0.1:$pages_port/" 2>/dev/null; then
  echo "FAIL: the pages emulator did not serve http://127.0.0.1:$pages_port/ within 120 s"
  tail -20 "$work/pages-dev.log"
  exit 1
fi
node web/page-check.mjs "http://127.0.0.1:$pages_port/" "$work/axe.min.js" --tokens web/packages/explorer/src/lib/tokens.css
stop_pages_dev
trap - EXIT

echo
echo "── the consumer ──"
# What a host installs, driven where it runs: the tarball above extracted
# into a scratch project, every subpath the README names resolved through
# node's own resolver, and a page built from it with the component mounted
# twice. Two mounts is the case the component's defaults are written for and
# the one no single-mount page can check.
node web/consumer-check.mjs "$work/$tarball" "$work/axe.min.js"

echo
echo "── page timing ──"
# The keystroke is measured where the reader will meet it. It is a
# release-time measurement on an idle machine and never a CI job — the CPU
# guard refuses a number taken on a busy one, and a job that always refuses is
# a vacuous pass wearing a green tick.
if timing=$(node web/page-timing.mjs "$dist" "$work/fifty-statements.json" 2>&1); then
  within_budget=yes
else
  within_budget=no
fi
echo "$timing"
# The measurement's own provenance, checked whether or not the number was
# inside the budget: a keystroke number printed without the machine it was
# taken on — the total load and the busiest process on it, before and after —
# or taken over fewer keystrokes than the launch standard asks for, is a
# different number with the same name. A run that refused to measure at all
# has no provenance to check and says so itself.
if printf %s "$timing" | grep -qF -- "page timing in Chrome/"; then
  for evidence in "background load before Chrome started" "background load after Chrome was gone" "busiest process" "over 100 keystrokes"; do
    if ! printf %s "$timing" | grep -qF -- "$evidence"; then
      echo "FAIL: the timing did not report \"$evidence\"; a number without its provenance is not a measurement"
      exit 1
    fi
  done
fi
[ "$within_budget" = yes ] || exit 1
