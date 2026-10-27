# 09 — GitHub subjects beginning with one prefix

The policy trusts GitHub's provider on condition that `aud` is `sts.amazonaws.com`, under
`StringEquals`, and `sub` matches `repo:acme/api:*`, under `StringLike`.

**Expected.** Grant 1 → **outsider**, exact: the owner `acme`, read from the subject's literal
text, not declared. It is the policy's only grant, nothing else lets anyone in, and its pattern
has one `*`, at the end, and no `?`, so the headline says how far it reaches: "Only tokens whose
subject begins repo:acme/api: can assume this role." The ring's sentence and the question are as
in case 08.

**Why.** Under `StringLike`, a `*` stands for any run of characters, none included, so a pattern
whose one wildcard ends it admits every subject that begins with the text before it, and no other.
A pattern with a wildcard anywhere else, a `?`, or a second star is not one prefix, and its
headline is as before. As in case 08, the headline quotes the prefix and names no repository.
