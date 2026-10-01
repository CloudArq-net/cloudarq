# 03 — a whole organisation, pinned by its immutable id

**The document.** `aud`, `repository_owner_id` and a `repo:acme/*` pattern on `sub`; the
reasoning for the policy itself is in `testdata/grants/03-whole-organisation/rationale.md`.

**What the golden pins.**

- Three claims in the engine's claim order, one row each, with the line and the operator each
  key is written under. The line numbers are the document's own: 13, 14 and 17.
- One term, so no `alternative 1 of 2` heading: that heading appears only where the admitted
  set is a union, and printing it over a single term would be the command inventing structure
  the answer does not have.
- The `IN WORDS` column saying `exactly this value` for `repository_owner_id`, not `exactly
  this id`: the words come from the claim's noun, and the report names only the three claims
  whose nouns are standard. Which claim names an organisation belongs to the registry, and
  the report does not guess it.

**Why this is the right answer.** The pair is a conjunction: the glob alone would admit a
namespace re-registered after a rename, and the owner id closes that. The sentence joins the
three with `and`, which is what a term is.
