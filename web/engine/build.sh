#!/usr/bin/env bash
# Builds the engine as a WebAssembly module and checks the build.
#
# In order: vet, the TinyGo build and wasm-opt, the module's size against its
# budget, that it links the census's tenancy data and not the census whole,
# the loader's own tests, the differential that holds every answer to the
# native engine's byte for byte, the entry's refusal of depth, where the heap
# settles, the loader's replacement of an instance past its memory bound and
# after a trap, and what -opt=z would cost. Every step prints what it
# measured; a step that cannot run fails the build rather than printing a
# pass.
#
# It needs Go, TinyGo 0.42.0, Binaryen's wasm-opt, brotli and a Node that runs
# TypeScript by stripping its types. It was last run with Go 1.27.1, TinyGo
# 0.42.0, wasm-opt version 132, brotli 1.2.0 and Node 22.21.0.
#
#   WORK=<dir> web/engine/build.sh    writes the module and the intermediate
#                                     files under <dir>; without WORK they go
#                                     to a new temporary directory
set -euo pipefail
cd "$(dirname "$0")/../.."

budget_brotli=400000          # bytes, measured as brotli -q 11
work=${WORK:-$(mktemp -d)}
mkdir -p "$work"

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
# target, is the fixture that proves the loader recovers from a trap; it is
# not the module anyone runs.
#
# -opt=s and wasm-opt -Os rather than z. A caller that re-reads a policy as it
# is edited calls the engine on every change, and that call is the largest
# single cost of each change, so the bytes z would save are not bought with
# the time it costs. The last step below measures both on every build, so the
# choice can be revisited from numbers.
#
# -panic=trap: a panic is a trap, without its message text, which is the
# only thing given up. It measured about 6.3 KB smaller gzipped, at no
# measurable cost in time, and the loader replaces an instance that trapped
# (web/engine/engine.ts). The trapping fixture is built the same way, so that
# the recovery it proves is the real module's.
#
# The version the findings name is the commit's, as git describes it: the tag
# alone on a release, as `go install …@v0.2.0` records it for the command.
version=$(git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)
version=${version#v}
export CLOUDARQ_ENGINE_VERSION="$version"
stamp=(-ldflags "-X main.version=$version")
tinygo build -o "$work/engine.wasm" -target web/wasm/target.json -buildmode=c-shared -scheduler=none -opt=s -no-debug -panic=trap "${stamp[@]}" ./web/wasm
tinygo build -o "$work/trapping.wasm" -target wasm -buildmode=c-shared -scheduler=none -opt=s -no-debug -panic=trap "${stamp[@]}" ./web/wasm
wasm-opt -Os --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext \
  --enable-mutable-globals --enable-reference-types --enable-multivalue \
  "$work/engine.wasm" -o "$work/cloudarq.wasm"
go build -o "$work/native" ./web/wasm/native
echo "built $work/cloudarq.wasm"

echo
echo "── size ──"
raw=$(stat -f %z "$work/cloudarq.wasm" 2>/dev/null || stat -c %s "$work/cloudarq.wasm")
gz=$(gzip -9 -c "$work/cloudarq.wasm" | wc -c | tr -d ' ')
br=$(brotli -q 11 -c "$work/cloudarq.wasm" | wc -c | tr -d ' ')
before=$(stat -f %z "$work/engine.wasm" 2>/dev/null || stat -c %s "$work/engine.wasm")
echo "tinygo:   $before bytes raw"
echo "wasm-opt: $raw bytes raw, $gz bytes gzip -9, $br bytes brotli -q 11"

echo
echo "── the census the engine links ──"
# The engine reads the census through its tenancy sub-package, a few
# kilobytes, and never the census whole, which, the one time the engine
# reached it, took the engine over 400,000 bytes gzipped. The keys below
# are the whole census's and not the sub-package's: each is checked to be
# so, in the census the build read, and a module carrying any of them has
# linked the whole.
census_dir=$(go list -m -f '{{.Dir}}' github.com/CloudArq-net/issuers)
root_keys="vendor_example_note control_test_result discovery_status jwks_status self_hosted_variant aud_evidence subject_examples"
checked=0
for key in $root_keys; do
  if ! grep -q -F "\"$key\"" "$census_dir/issuers.json" || grep -q -F "\"$key\"" "$census_dir/tenancy/tenancy.json"; then
    echo "FAIL: $key is not a key of the census whole alone, so its absence would prove nothing"
    exit 1
  fi
  if grep -a -q -F "$key" "$work/cloudarq.wasm"; then
    echo "FAIL: the engine carries $key, a key of the census whole: the whole census is linked into it"
    exit 1
  fi
  checked=$((checked + 1))
done
if [ "$checked" -eq 0 ]; then
  echo "FAIL: no key of the census whole was looked for, so nothing was examined"
  exit 1
fi
echo "census: none of the $checked keys only the census whole carries is in the engine; it links the tenancy data alone ($census_dir)"

if [ "$br" -gt "$budget_brotli" ]; then
  echo "FAIL: $br bytes brotli exceeds the budget of $budget_brotli"
  exit 1
fi
echo "size: $br bytes brotli is within the budget of $budget_brotli"

echo
echo "── the loader's tests ──"
CLOUDARQ_WASM="$work/cloudarq.wasm" CLOUDARQ_TRAPPING_WASM="$work/trapping.wasm" node --test web/engine/test/*.test.ts

echo
echo "── differential, memory, engine timing, recovery ──"
if ! differential=$(node web/engine/diff.mjs "$work/cloudarq.wasm" "$work/native" "$work" "$work/trapping.wasm" 2>&1); then
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
# size, its compressed size against the budget and its time on the
# 50-statement policy the differential wrote.
tinygo build -o "$work/engine-z.wasm" -target web/wasm/target.json -buildmode=c-shared -scheduler=none -opt=z -no-debug -panic=trap "${stamp[@]}" ./web/wasm
wasm-opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext \
  --enable-mutable-globals --enable-reference-types --enable-multivalue \
  "$work/engine-z.wasm" -o "$work/cloudarq-z.wasm"
br_z=$(brotli -q 11 -c "$work/cloudarq-z.wasm" | wc -c | tr -d ' ')
opt_s="$work/cloudarq.wasm" opt_z="$work/cloudarq-z.wasm" fifty="$work/fifty-statements.json" \
br_s="$br" br_z="$br_z" budget="$budget_brotli" node --input-type=module -e '
import { readFileSync } from "node:fs";
const { loadEngine } = await import("./web/engine/engine.ts");
const { opt_s, opt_z, fifty: fiftyPath, br_s, br_z, budget } = process.env;
const fifty = readFileSync(fiftyPath, "utf8");
const medianMs = async path => {
  const engine = await loadEngine(await WebAssembly.compile(readFileSync(path)));
  for (let i = 0; i < 20; i++) engine.admits(fifty);
  const runs = [];
  for (let i = 0; i < 50; i++) { const t = performance.now(); engine.admits(fifty); runs.push(performance.now() - t); }
  return runs.sort((a, b) => a - b)[25];
};
const s = await medianMs(opt_s);
const z = await medianMs(opt_z);
console.log(`-opt=s, the module:      ${br_s} bytes brotli, admits on 50 statements in node: median ${s.toFixed(2)} ms`);
console.log(`-opt=z, for comparison: ${br_z} bytes brotli, median ${z.toFixed(2)} ms`);
console.log(`the trade: ${br_s - br_z} bytes saved for ${(z - s).toFixed(2)} ms added to every call, against ${budget - br_s} bytes of headroom in the ${budget} byte budget`);
'

echo
echo "the engine: $work/cloudarq.wasm"
