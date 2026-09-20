// The differential: the engine compiled to WebAssembly must render every
// document byte for byte as the native engine does, for admits and for
// explain, over the corpus and over the shapes a paste can take that no
// fixture has: nesting at and past the entry's bound, a member the grammar
// does not define, a document past the engine's bound, a token nested too
// deep. Then the entry's refusal of depth with the engine answering after
// it; the engine's own time on a 50-statement policy in node, which is the
// engine's number, not the page's (the page is timed in Chrome by
// web/page-timing.mjs); where the heap stands over repeated calls on that
// policy and on the largest document the engine reads; the glue's
// replacement of an instance past its memory bound; and the glue's
// recovery from a trap, proven on a build that still traps.
//
// The heap's levels are printed as one run's sample and asserted as bounds,
// never as equalities: where TinyGo's collector doubles moves between runs on
// the same build, so a gate written as "the level at call 100 equals the
// level at call 200" fails at random on a correct engine.
//
//   node web/diff.mjs <engine.wasm> <native helper binary> <work dir> [<trapping.wasm>]
//
// Exits non-zero on the first difference; a difference is a blocker, not a
// tolerance. Nothing here evaluates: both sides are the same Go, and the
// comparison is bytes.
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { performance } from "node:perf_hooks";

const [wasmPath, nativeBin, work, trappingPath] = process.argv.slice(2);
if (!wasmPath || !nativeBin || !work) {
  console.error("usage: node web/diff.mjs <engine.wasm> <native helper> <work dir> [<trapping.wasm>]");
  process.exit(2);
}

// wasm_exec.js defines globalThis.Go as a side effect of being evaluated;
// the page's own loader then installs admits and explain, so the glue the
// differential exercises is the glue the page runs
await import("./wasm_exec.js");
const { loadEngine } = await import("./app.js");
const engineModule = await WebAssembly.compile(readFileSync(wasmPath));
const engine = await loadEngine(engineModule);
for (const name of ["admits", "explain"]) {
  if (typeof globalThis[name] !== "function") {
    console.error(`the engine did not install ${name} on globalThis`);
    process.exit(1);
  }
}

const native = (...args) => execFileSync(nativeBin, args, { maxBuffer: 64 << 20 });

const corpus = [
  ...readdirSync("testdata/policies").filter(f => f.endsWith(".json")).sort().map(f => join("testdata/policies", f)),
  ...readdirSync("testdata/grants").sort().map(d => join("testdata/grants", d, "aws.json")),
];

// policyOf is a policy of n statements, each its own repository, so the
// answer has n grants
function policyOf(n) {
  const statements = [];
  for (let i = 0; i < n; i++) {
    statements.push({
      Sid: `Repository${i}`,
      Effect: "Allow",
      Principal: { Federated: "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" },
      Action: "sts:AssumeRoleWithWebIdentity",
      Condition: {
        StringEquals: {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:repository_id": String(100000 + i),
        },
        StringLike: { "token.actions.githubusercontent.com:sub": `repo:acme/service-${i}:*` },
      },
    });
  }
  return JSON.stringify({ Version: "2012-10-17", Statement: statements }, null, 2);
}

// The engine's bounds, as the report package states them; the shapes below
// sit on either side of each. deepObjects(n) nests n + 1 objects.
const maxDocumentBytes = 256 << 10;
const maxTokenBytes = 16 << 10;
const maxDocumentNesting = 1000;
const maxTokenNesting = 500;
const deepObjects = n => "{" + '"a":{'.repeat(n) + "}".repeat(n + 1);
const padded = (n, head, tail) => head + "a".repeat(n - head.length - tail.length) + tail;
const shapes = {
  "objects-125-deep.json": deepObjects(125),
  "objects-200-deep.json": deepObjects(200),
  "objects-999-deep.json": deepObjects(maxDocumentNesting - 1),
  "objects-1000-deep.json": deepObjects(maxDocumentNesting),
  "objects-1001-deep.json": deepObjects(maxDocumentNesting + 1),
  "arrays-3000-deep.json": '{"Statement":' + "[".repeat(3000) + "]".repeat(3000) + "}",
  "condition-value-900-deep.json": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":' + "[".repeat(900) + "]".repeat(900) + "}}}]}",
  "misspelt-member.json": '{"Version":"2012-10-17","Statement":[],"Statment":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}}',
  "scalar-statement.json": '{"Version": 2012, "Id": 5, "Statement": "nope"}',
  "member-beyond-ascii.json": '{"Version":"2012-10-17","Statement":[{"Sid":"Caf\\u00e9 \\ud83d\\ude00","Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","St\\u00e4tement\\u2603":1}],"\\u00dcnknown\\ud83d\\ude00":{"x":"y"}}',
  "at-the-bound.json": padded(maxDocumentBytes, '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity"}],"Id":"', '"}'),
  "past-the-bound.json": padded(maxDocumentBytes + 1, '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity"}],"Id":"', '"}'),
  "not-json.txt": "{ this is not a policy",
  "fifty-statements.json": policyOf(50),
};
for (const [name, text] of Object.entries(shapes)) writeFileSync(join(work, name), text);
const fifty = shapes["fifty-statements.json"];
const documents = [...corpus, ...Object.keys(shapes).map(name => join(work, name))];

// Tokens every document is explained against: one no corpus grant admits on
// every claim, so that explain's rejection paths are compared as well as its
// admitted ones; a whole token; and shapes at and past the reader's bounds.
const segment = text => Buffer.from(text).toString("base64url");
const deepToken = n => '{"a":' + "[".repeat(n) + "]".repeat(n) + "}";
const tokens = {
  "foreign-token.json": JSON.stringify({ iss: "https://token.actions.githubusercontent.com", aud: "https://github.com/acme", sub: "repo:acme-evil/infra:ref:refs/heads/main", repository_id: "1" }, null, 2),
  "whole-token.txt": "eyJhbGciOiJSUzI1NiJ9." + segment('{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:ref:refs/heads/main","repository_owner_id":"123456","repository_id":"456789"}') + ".c2ln",
  "token-499-deep.json": deepToken(maxTokenNesting - 1),
  "token-500-deep.json": deepToken(maxTokenNesting),
  "token-9990-deep.json": deepToken(9990),
  "token-at-the-bound.json": padded(maxTokenBytes, '{"sub":"', '"}'),
  "token-past-the-bound.json": padded(maxTokenBytes + 1, '{"sub":"', '"}'),
  "token-not-json.txt": "not a token",
};
for (const [name, text] of Object.entries(tokens)) writeFileSync(join(work, name), text);

let differences = 0;
let explains = 0;
function compare(label, fromWasm, fromNative) {
  if (Buffer.from(fromWasm, "utf8").equals(fromNative)) return;
  differences++;
  console.error(`DIFFERENT: ${label}`);
  console.error(`  wasm:   ${fromWasm.slice(0, 400)}`);
  console.error(`  native: ${fromNative.toString("utf8").slice(0, 400)}`);
}

for (const file of documents) {
  const text = readFileSync(file, "utf8");
  const fromWasm = admits(text);
  compare(`admits ${file}`, fromWasm, native("admits", file));

  const against = Object.keys(tokens).map(name => [name, join(work, name)]);
  for (const grant of JSON.parse(fromWasm).grants ?? []) {
    if (!grant.witness) continue;
    const path = join(work, `witness-${grant.number}.json`);
    writeFileSync(path, grant.witness);
    against.push([`witness of grant ${grant.number}`, path]);
  }
  for (const [label, path] of against) {
    explains++;
    compare(`explain ${file} with ${label}`, explain(text, readFileSync(path, "utf8")), native("explain", file, path));
  }
}
console.log(`differential: ${documents.length} documents (${corpus.length} of the corpus, ${Object.keys(shapes).length} generated) through admits, ${explains} explain calls, ${differences} differences`);
if (documents.length === 0 || differences > 0) process.exit(1);

// Depth. A document nested 200 deep trapped the engine on the toolchain's
// 64 KB stack, and the trap was permanent; the shipped build answers it,
// refuses one past the bound in a sentence that names the depth and the
// bound, and answers the document after either as it would have anyway.
{
  const answered = JSON.parse(admits(deepObjects(200)));
  if (answered.error || answered.grants.length !== 1) {
    console.error(`FAIL: the document nested 201 deep was not answered: ${JSON.stringify(answered).slice(0, 200)}`);
    process.exit(1);
  }
  const refused = JSON.parse(admits(deepObjects(maxDocumentNesting)));
  const sentence = `the document is nested ${maxDocumentNesting + 1} levels deep; the engine reads up to ${maxDocumentNesting} levels, and level ${maxDocumentNesting + 1} opens at byte ${5 * maxDocumentNesting}`;
  if (refused.error !== sentence || refused.document || refused.grants.length !== 0) {
    console.error(`FAIL: the document nested ${maxDocumentNesting + 1} deep was not refused as expected: ${JSON.stringify(refused).slice(0, 300)}`);
    process.exit(1);
  }
  const good = "testdata/grants/03-whole-organisation/aws.json";
  const after = admits(readFileSync(good, "utf8"));
  if (!Buffer.from(after, "utf8").equals(native("admits", good)) || JSON.parse(after).grants.length !== 1) {
    console.error("FAIL: the document after the refusal was not answered as native answers it");
    process.exit(1);
  }
  console.log(`depth: 201 levels answered (${answered.grants.length} grant), ${maxDocumentNesting + 1} levels refused ("${refused.error}"), the next document answered as native does; engine replaced ${engine.replacements()} times`);
}

// The engine's own time, in node, on the 50-statement policy: the engine's
// number, which the page's re-evaluation includes and exceeds.
const grants = JSON.parse(admits(fifty)).grants.length;
if (grants !== 50) {
  console.error(`expected 50 grants from the 50-statement policy, got ${grants}`);
  process.exit(1);
}
for (let i = 0; i < 20; i++) admits(fifty); // warm the module before timing it
const samples = [];
for (let i = 0; i < 50; i++) {
  const t0 = performance.now();
  admits(fifty);
  samples.push(performance.now() - t0);
}
samples.sort((a, b) => a - b);
const median = samples[Math.floor(samples.length / 2)];
console.log(`engine timing: admits() on 50 statements (${grants} grants, ${fifty.length} bytes) in node: median ${median.toFixed(2)} ms, min ${samples[0].toFixed(2)} ms, max ${samples[samples.length - 1].toFixed(2)} ms over ${samples.length} runs`);

// The heap. Linear memory never shrinks and the collector doubles it rather
// than compact, so a document re-read on every keystroke must settle. Where
// a run's doublings land is not deterministic: on the same build the
// largest document has reached its level at call 5 in one run and call 84
// in the next, and an earlier version of this gate asserted that the level
// at call 100 equalled the level at call 200, which is a statement about
// when rather than about what and failed at random on a correct build.
//
// What is asserted here holds on every run, and each assertion says what it
// rests on.
//
//   · The document a reader types into costs no instance replacement over
//     400 calls, and — because nothing was replaced, so the level is that
//     one instance's — settles at or under the level recorded below. An
//     engine that needed more would read higher or cost a replacement, and
//     either fails. This is the fact the page depends on: a replacement
//     costs the next keystroke about 80 ms.
//   · The largest document the engine reads settles at or under the level
//     recorded below, measured with the ceiling lifted. Past the ceiling
//     the glue replaces the instance, and memoryBytes() then reads the
//     fresh one: a hungrier engine reads *lower*, not higher, so a level
//     taken under the shipped bound is an under-approximation of what the
//     engine asked for. Measured without a ceiling there is nothing to
//     replace and the number is the engine's own.
//   · Nothing exceeds one doubling of the bound. This one holds by
//     construction of the glue rather than by the engine's behaviour — the
//     instance is replaced past the bound and the collector grows by
//     doubling — and it is here so that a glue that stopped replacing is
//     caught. What proves the replacement happens at all is the small-bound
//     block further down, which is deterministic.
//
// Every measurement runs on a fresh instance. Four of them on one instance
// measures the sequence rather than the document, and that is how the
// earlier gate came to report a level of 144 MB followed by one of 72.
const largest = policyOf(Math.floor(maxDocumentBytes / (policyOf(50).length / 50)) - 2);
if (largest.length > maxDocumentBytes) {
  console.error(`the largest generated document is ${largest.length} bytes, past the bound of ${maxDocumentBytes}`);
  process.exit(1);
}
const mb = n => `${(n / 1048576).toFixed(0)} MB`;
const memoryBound = 1 << 28;
// Past anything either document has reached, so the instance measured under
// it is never replaced and its level is the engine's own. Written as a power
// and not as a shift: 1 << 31 is negative in JavaScript, which made every
// call exceed the bound and replaced the instance 400 times — the check that
// the unbounded run replaced nothing is what said so.
const noCeiling = 2 ** 31;
// Ceilings and not equalities, because a run that settles lower is a run
// that cost less. Measured 2026-09-20: the 50-statement policy at 18 MB on
// twelve of sixteen fresh instances and 36 MB on four — always 18 MB through
// its 200 admits, the further doubling arriving somewhere in the 200 explain
// calls — and the largest document, with the ceiling lifted, at 288 MB on two
// of five and 576 MB on three. The collector grows by doubling, so one
// doubling is the unit of the spread, the ceiling is the higher of the two,
// and a regression is caught when it costs a further doubling. A ceiling set
// at the lower of the two fails about one run in four on a correct build,
// which is the nondeterminism this gate was rewritten to remove. Under the
// shipped bound the largest document reads 144 MB, a quarter of what it asked
// for, because it is replaced before it gets there: that number measures the
// glue, not the engine.
// The keystroke path is admits, and it is the half of the 400 calls that does
// not spread: 18 MB after its 200 calls on sixteen fresh instances of sixteen,
// 9 MB on one of the runs before them. It carries its own ceiling so that the
// wider one below cannot hide a doubling in the path a reader pays for.
const readerAdmitsBytes = 18 * 1048576;
const readerSettledBytes = 36 * 1048576;
const largestSettledBytes = 576 * 1048576;

// heap runs each phase 200 times on one fresh instance and prints where the
// heap stood after the first call, the hundredth and the two hundredth.
// Those levels, the peak and the replacement count are one run's sample and
// are printed as such: on five runs of the same build the largest document
// reached its last doubling at call 5 in one and call 84 in another, and its
// peak read 144 MB in one and 288 in the next. What the gate asserts is
// underneath them and holds on every run.
async function heap(label, phases, bound = memoryBound) {
  const instance = await loadEngine(engineModule, { memoryBound: bound });
  const after = {};
  const readings = phases.map(([name, call]) => {
    const at = {};
    for (let i = 1; i <= 200; i++) {
      call();
      if (i === 1 || i === 100 || i === 200) at[i] = instance.memoryBytes();
    }
    after[name] = at[200];
    return `${name} ${mb(at[1])} after 1, ${mb(at[100])} after 100, ${mb(at[200])} after 200`;
  });
  console.log(`memory, this run's sample: ${label}, on a fresh instance: ${readings.join("; ")}; peak ${mb(instance.peakMemoryBytes())}, engine replaced ${instance.replacements()} ${instance.replacements() === 1 ? "time" : "times"}`);
  return { after, settled: instance.memoryBytes(), peak: instance.peakMemoryBytes(), replaced: instance.replacements() };
}

const grantsOfLargest = JSON.parse(admits(largest)).grants.length;
const reader = await heap(`the 50-statement policy (${fifty.length} bytes), 200 admits then 200 explain`, [
  ["admits", () => admits(fifty)],
  ["explain", () => explain(fifty, tokens["foreign-token.json"])],
]);
if (reader.replaced > 0) {
  console.error(`FAIL: the document a reader types into cost ${reader.replaced} instance replacement(s) over 400 calls; each one costs the keystroke after it about 80 ms`);
  process.exit(1);
}
if (reader.after.admits > readerAdmitsBytes) {
  console.error(`FAIL: the keystroke path stood at ${mb(reader.after.admits)} after 200 admits on the document a reader types into, past the ${mb(readerAdmitsBytes)} recorded for it`);
  process.exit(1);
}
if (reader.settled > readerSettledBytes) {
  console.error(`FAIL: the document a reader types into settled at ${mb(reader.settled)} on one instance, past the ${mb(readerSettledBytes)} recorded for it`);
  process.exit(1);
}
console.log(`memory: the 50-statement policy cost no replacement over 400 calls, stood at ${mb(reader.after.admits)} after its 200 admits and settled at ${mb(reader.settled)}, at or under the ${mb(readerAdmitsBytes)} and ${mb(readerSettledBytes)} recorded for them; nothing was replaced, so those levels are one instance's own`);
const biggest = await heap(`the largest document (${largest.length} bytes, ${grantsOfLargest} grants), 200 admits then 200 explain`, [
  ["admits", () => admits(largest)],
  ["explain", () => explain(largest, tokens["foreign-token.json"])],
]);
// the same document again with the ceiling lifted: nothing is replaced, so
// what memoryBytes() reads is what the engine asked for rather than what
// the instance after it starts at
const unbounded = await heap(`the largest document again, with the ${mb(memoryBound)} ceiling lifted`, [
  ["admits", () => admits(largest)],
  ["explain", () => explain(largest, tokens["foreign-token.json"])],
], noCeiling);
if (unbounded.replaced > 0) {
  console.error(`FAIL: the instance measured without a ceiling was replaced ${unbounded.replaced} time(s), so its level is not one instance's; raise noCeiling past ${mb(unbounded.peak)}`);
  process.exit(1);
}
if (unbounded.settled > largestSettledBytes) {
  console.error(`FAIL: the largest document settled at ${mb(unbounded.settled)} with the ceiling lifted, past the ${mb(largestSettledBytes)} recorded for it`);
  process.exit(1);
}
console.log(`memory: the largest document settled at ${mb(unbounded.settled)} with the ceiling lifted, at or under the ${mb(largestSettledBytes)} recorded for it`);


// The replacement path, proven on a bound the largest document crosses on
// every run: the instance is replaced past it, and the call after answers
// as native does. Whether the shipped bound is crossed depends on where a
// run's doublings land, so this is what proves the ceiling.
{
  const small = await loadEngine(engineModule, { memoryBound: 1 << 25 });
  let calls = 0;
  while (small.replacements() === 0 && calls < 50) {
    explain(largest, tokens["foreign-token.json"]);
    calls++;
  }
  const after = admits(readFileSync("testdata/grants/03-whole-organisation/aws.json", "utf8"));
  const same = Buffer.from(after, "utf8").equals(native("admits", "testdata/grants/03-whole-organisation/aws.json"));
  console.log(`replacement: on a ${mb(1 << 25)} bound the engine was replaced after ${calls} explain ${calls === 1 ? "call" : "calls"} on the largest document (peak ${mb(small.peakMemoryBytes())}, now ${mb(small.memoryBytes())}); the call after ${same ? "answered as native does" : "DID NOT answer as native does"}`);
  if (small.replacements() === 0) {
    console.error(`FAIL: on a ${mb(1 << 25)} bound the engine was never replaced over ${calls} explain calls on the largest document, so the ceiling the tab's memory is held to is not enforced`);
    process.exit(1);
  }
  if (!same) {
    console.error("FAIL: the call after a replacement did not answer as native does, so a replaced engine answers differently from the one it replaced");
    process.exit(1);
  }
}

// The ceiling that follows from it, read off the two runs under the shipped
// bound. This one holds by construction — the instance is replaced past the
// bound and the collector grows by doubling — so it is here to catch a glue
// that stopped replacing, which the block above has just proven it does.
for (const [label, measured] of [["the 50-statement policy", reader], ["the largest document", biggest]]) {
  if (measured.peak > 2 * memoryBound) {
    console.error(`FAIL: ${label} reached ${mb(measured.peak)}, past one doubling of the ${mb(memoryBound)} bound`);
    process.exit(1);
  }
}
console.log(`memory: under the ${mb(memoryBound)} bound neither document exceeded one doubling of it, the ceiling the replacement above enforces`);

// Recovery. No document is known to trap the shipped build, so the glue's
// path through a trap is proven on a build of the same engine linked with
// the toolchain's 64 KB stack, which a document nested 125 levels deep,
// inside the entry's bound, overflows: the call throws, and the next call
// meets a live engine whose answer is the native one.
if (trappingPath) {
  await loadEngine(await WebAssembly.compile(readFileSync(trappingPath)));
  const deep = deepObjects(125);
  const good = readFileSync("testdata/grants/03-whole-organisation/aws.json", "utf8");
  let trapped = null;
  try {
    admits(deep);
  } catch (err) {
    trapped = err;
  }
  if (!trapped) {
    console.error("FAIL: the trapping build did not trap on the document nested 125 levels deep; the recovery path went unexercised");
    process.exit(1);
  }
  const after = [admits(good), explain(good, tokens["foreign-token.json"])];
  const expected = [native("admits", "testdata/grants/03-whole-organisation/aws.json"), native("explain", "testdata/grants/03-whole-organisation/aws.json", join(work, "foreign-token.json"))];
  const recovered = after.every((text, i) => Buffer.from(text, "utf8").equals(expected[i]));
  console.log(`recovery: the 64 KB-stack build trapped (${trapped.constructor.name}: ${trapped.message}); the next admits and explain ${recovered ? "answered as native does" : "DID NOT answer as native does"}`);
  if (!recovered) process.exit(1);
}
