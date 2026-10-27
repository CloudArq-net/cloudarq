# 08 — one GitHub subject, exactly

The policy trusts GitHub's provider on condition that `aud` is `sts.amazonaws.com` and `sub` is
`repo:acme/api:ref:refs/heads/main`, both under `StringEquals`.

**Expected.** Grant 1 → **outsider**, exact: the owner `acme`, read from the subject, not
declared. It is the policy's only grant, nothing else lets anyone in, and its subject is one value
holding no `*` or `?`, so the headline says how exact it is: "Only tokens whose subject is exactly
repo:acme/api:ref:refs/heads/main can assume this role." The ring's sentence stays "github:acme
can assume this role and is not declared as yours.", and the question stays "Is github:acme
yours?".

**Why.** `StringEquals` compares the subject as written, so a token whose subject is any other
text is not admitted, and with no other way in, no one else is either. Before this, the headline
read "A named outsider can assume this role.", as it does for a trust in every repository the
owner has. The headline quotes the subject and reads nothing else into it: the engine reads the
owner alone from `sub`, so it names no repository and no branch. The subject does not make the
owner the reader's, which the ring's sentence and the question still say.
