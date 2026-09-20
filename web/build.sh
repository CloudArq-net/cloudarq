#!/usr/bin/env bash
# Builds the explorer into web/dist and proves the build: the engine compiled
# to WebAssembly, its sizes against the budget, the greps and the token
# census that stand in for taste, the differential against the native engine
# over every document in the corpus and the generated shapes, the entry's
# refusal of depth, the heap's ceiling, the glue's recovery from a trap, the
# engine's own time in node, the page's behaviour in Chrome under the headers
# it will be hosted with, and the page's re-evaluation time in Chrome.
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
wasm-opt -Os --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext \
  --enable-mutable-globals --enable-reference-types --enable-multivalue \
  "$work/engine.wasm" -o "$dist/cloudarq.wasm"
go build -o "$work/native" ./web/wasm/native
# _headers is what Cloudflare Pages reads from the root of what it serves;
# it belongs beside the page in dist and is kept in web/ so that a clean
# build writes it rather than inheriting it
cp web/index.html web/app.js web/tokens.css web/app.css web/wasm_exec.js web/_headers "$dist/"
echo "built $dist/cloudarq.wasm and the page beside it, with the hosted headers in $dist/_headers"

echo
echo "── examples ──"
# the empty state offers three corpus documents, embedded in the page; they
# must be the corpus bytes, not a copy that drifted
node --input-type=module -e '
import { readFileSync } from "node:fs";
const html = readFileSync("web/index.html", "utf8");
let n = 0;
for (const [, name, text] of html.matchAll(/<script type="application\/json" data-example="([^"]+)">([^]*?)<\/script>/g)) {
  if (text !== readFileSync(`testdata/grants/${name}/aws.json`, "utf8")) {
    console.error(`FAIL: the example ${name} in web/index.html differs from testdata/grants/${name}/aws.json`);
    process.exit(1);
  }
  n++;
}
if (n === 0) { console.error("FAIL: no example is embedded in web/index.html"); process.exit(1); }
console.log(`examples: ${n} embedded documents equal their corpus files byte for byte`);
'

echo
echo "── the page's own rules ──"
# product/LAUNCH-STANDARD.md §3 and docs/ENGINEERING.md §9: the greps that
# stand in for taste under a deadline. They were run by hand until now, which
# is not a gate. Declarations are read with comments stripped, because a
# comment declares nothing: the file says 800px in prose twice and the one
# literal length outside the tokens is the media query, which a custom
# property cannot express.
node --input-type=module -e '
import { readFileSync } from "node:fs";
const read = path => readFileSync(`web/${path}`, "utf8");
const strip = (path, text) => path.endsWith(".html")
  ? text.replace(/<!--[^]*?-->/g, "")
  : text.replace(/\/\*[^]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
const lines = paths => paths.flatMap(path => strip(path, read(path)).split("\n").map((text, i) => [`${path}:${i + 1}`, text]));
const page = ["index.html", "app.css", "tokens.css", "app.js"];
const styling = ["index.html", "app.css", "app.js"];

let broken = 0;
// A rule fires on every line its pattern matches, except the ones "allowed"
// names. The default allows nothing: a default that allowed everything made
// six of the eight greps below print "clean" over a page carrying a
// box-shadow and a literal duration, which is how they were found.
const rule = (name, paths, pattern, allowed = () => false) => {
  const hits = lines(paths).filter(([, text]) => pattern.test(text)).filter(([at, text]) => !allowed(at, text));
  console.log(`  ${hits.length === 0 ? "clean" : "FAIL "} ${name}: ${lines(paths).length} declaration lines over ${paths.join(", ")}${hits.length ? `\n         ${hits.map(([at, text]) => `${at}: ${text.trim()}`).join("\n         ")}` : ""}`);
  if (hits.length) broken++;
};

// the Makefile css target greps every file under web/ for the same idioms,
// this script included, so the words are spelt with a character class here:
// the pattern still matches them in the page, and this file never carries them
rule("no decoration", page, /gr[a]dient|blur-\[|backdrop-f[i]lter|cyb[e]r-|drop-sh[a]dow|box-sh[a]dow|border-radius: *([4-9]|[1-9][0-9])px/);
rule("no colour outside the tokens", styling, /#[0-9a-fA-F]{3,8}\b|transparent|currentColor|rgb\(|hsl\(/);
rule("no length outside the tokens", styling, /[0-9](px|rem|em|ch|lh)\b/, at => at.startsWith("app.css:") && /@media/.test(lines(["app.css"]).find(([a]) => a === at)[1]));
// motion explains state and never decorates: every transition and keyframe is
// declared once in tokens.css under a named motion token, so a literal
// duration anywhere else is a motion nobody declared
rule("no motion outside the tokens", styling, /transition|animation|@keyframes|scroll-behavior/);
rule("no literal duration outside the tokens", ["index.html", "app.css"], /[0-9](\.[0-9]+)?m?s\b/);
rule("no verdict in the page", page, /severity|critical|posture|verdict|badge|hero|dashboard|!important|TODO|FIXME|XXX/i);
// "secure" is a permitted adjective and "security" a forbidden noun; the
// hosted headers and the browser API that reports their refusals carry the
// word as a name of the platform, which is not the product speaking
const platform = /Content-Security-Policy|Strict-Transport-Security|securitypolicyviolation|source === "security"/;
rule("the page never says the forbidden noun", page, /secur/i);
// build.sh is not in that list because it carries the pattern: a scanner
// that scans itself reports its own rule and nothing else
rule("nothing else says it but the platform", ["_headers", "page-check.mjs", "page-timing.mjs", "diff.mjs"], /secur/i, (at, text) => platform.test(text));

// Every token declared in tokens.css is read by name somewhere, and every
// name the page reads is declared: the second half catches a token renamed
// in one file and not the other, which no stylesheet reports.
const declarations = text => [...text.matchAll(/(--[a-z0-9-]+)\s*:/g)].map(m => m[1]);
const tokens = [...new Set(declarations(read("tokens.css")))];
const all = page.map(read).join("\n");
const declared = new Set(page.flatMap(path => declarations(read(path))));
const unused = tokens.filter(t => !all.includes(`var(${t})`) && !all.includes(`"${t}"`));
const used = [...new Set([...all.matchAll(/var\((--[a-z0-9-]+)/g)].map(m => m[1]))];
const undeclared = used.filter(t => !declared.has(t));
console.log(`  ${unused.length || undeclared.length ? "FAIL " : "clean"} every token is declared and consumed: ${tokens.length} declared in tokens.css, ${used.length} names read across the page${unused.length ? `; unused: ${unused.join(", ")}` : ""}${undeclared.length ? `; never declared: ${undeclared.join(", ")}` : ""}`);
if (unused.length || undeclared.length) broken++;
if (tokens.length === 0) { console.log("  FAIL  no token was read out of tokens.css, so nothing was checked"); broken++; }
if (broken) { console.error(`FAIL: ${broken} of the page rules are broken`); process.exit(1); }
console.log(`the page rules: ${tokens.length} tokens and 8 greps over the page, all clean`);
'

echo
echo "── size ──"
raw=$(stat -f %z "$dist/cloudarq.wasm" 2>/dev/null || stat -c %s "$dist/cloudarq.wasm")
gz=$(gzip -9 -c "$dist/cloudarq.wasm" | wc -c | tr -d ' ')
br=$(brotli -q 11 -c "$dist/cloudarq.wasm" | wc -c | tr -d ' ')
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
if ! differential=$(node web/diff.mjs "$dist/cloudarq.wasm" "$work/native" "$work" "$work/trapping.wasm" 2>&1); then
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
shipped="$dist/cloudarq.wasm" for_size="$work/cloudarq-z.wasm" fifty="$work/fifty-statements.json" \
gz_shipped="$gz" gz_for_size="$gz_z" budget="$budget_gzip" node --input-type=module -e '
import { readFileSync } from "node:fs";
await import("./web/wasm_exec.js");
const { loadEngine } = await import("./web/app.js");
const { shipped, for_size, fifty: fiftyPath, gz_shipped, gz_for_size, budget } = process.env;
const fifty = readFileSync(fiftyPath, "utf8");
const medianMs = async path => {
  await loadEngine(await WebAssembly.compile(readFileSync(path)));
  for (let i = 0; i < 20; i++) admits(fifty);
  const runs = [];
  for (let i = 0; i < 50; i++) { const t = performance.now(); admits(fifty); runs.push(performance.now() - t); }
  return runs.sort((a, b) => a - b)[25];
};
const s = await medianMs(shipped);
const z = await medianMs(for_size);
console.log(`-opt=s, shipped:     ${gz_shipped} bytes gzipped, admits on 50 statements in node: median ${s.toFixed(2)} ms`);
console.log(`-opt=z, not shipped: ${gz_for_size} bytes gzipped, median ${z.toFixed(2)} ms`);
console.log(`the trade: ${gz_shipped - gz_for_size} bytes saved for ${(z - s).toFixed(2)} ms added to the engine call inside every keystroke, against ${budget - gz_shipped} bytes of headroom in the ${budget} byte budget`);
'

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
echo "── page check ──"
node web/page-check.mjs "$dist" "$work/axe.min.js" "npx --yes wrangler@$wrangler_version"

echo
echo "── page timing ──"
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
