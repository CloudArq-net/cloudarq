# 52 — a document that holds no statement

A policy's `Version` and `Id` with nothing after them: what a paste cut short looks like.

**Expected.** No grant and no ring. The headline says the document holds no statement, so who can
assume the role is not known; never *"Nothing outside your company can assume this role."* Nothing
follows it: no ring, no line beside the rings, no owners echoed and no bounds.

**Why.** The IAM grammar gives a policy a statement block, marked required where the version and the
id are marked optional, and the block is a list of statements. A document without one is not a trust
policy IAM holds, so it is not the role's, and nothing in it can be placed in a ring. The parser says
so in the document's note: "the document has no Statement member; the IAM grammar requires one". The
sentence for an empty set of rings is the worst output this engine can print when it is wrong; said
of a document that cannot be the role's, it would be a finding about a role the engine never saw.
Five empty rings marked exact would say it row by row, whatever the headline says, so none is
printed.

> "policy  = {
>      <version_block?>,
>      <id_block?>,
>      <statement_block>
> }" — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html · read 2026-09-23
> "<statement_block> = "Statement" : [ <statement>, <statement>, ... ]" — the same page · read 2026-09-23
