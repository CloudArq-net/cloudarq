# 05 — the repository id, and the claim that is not there

**The document.** `aud` and `repository_id`. No constraint on `sub`.

**What the golden pins.**

- Two claim rows, and under them the row every term ends with. `sub` is not a claim row:
  the table shows the claims the admitted set names, and a claim nothing constrains is not
  one of them — it is covered by `any other claim  any  unconstrained`, which is where the
  reader is told so.
- No `sub  any  any subject · no condition names it` row, which 06 does have. That row is
  the answer's, not the renderer's, and it appears only where nothing but the audience is
  named. Here `repository_id` is named, so the identity is bounded and the row would be
  false.
- The witness carries `aud` and `repository_id` and no `sub`, with the engine's caption
  saying that a claim not shown is unconstrained.

**Why this is the right answer.** The repository is pinned by an id that GitHub never
reuses, so every workflow in that repository is admitted and nothing outside it is. The
answer says which claims decided that and stays silent about the ones that did not.
