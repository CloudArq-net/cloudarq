# 15 — one account, in a list of one, in the only statement

The policy's only statement, which has no Sid, lists one account under `AWS`, `777788889999`, by its
bare id, in a list of one. The policy is written in the 2008-10-17 language, and the statement also
allows `sts:TagSession`.

**Expected.** The account's fix is proven and replaces the whole policy (`removes` is `policy`):
"Replace the whole trust policy with one that lets no one in: statement 1, lines 4-15, is its only
statement, the only principal it names is "777788889999", and IAM refuses a trust policy with no
statement." The replacement keeps `"Version": "2008-10-17"` as the original writes it.

**Why.** Removing the string from a list of one would leave `"AWS": []`, and removing `AWS` would
leave `"Principal": {}`: neither names anyone, so the least removal is the statement, and with it
every statement of the policy, as in case 11. The engine reads a principal as getting in through
`sts:AssumeRole`, `sts:AssumeRoleWithWebIdentity` or `sts:AssumeRoleWithSAML` alone, and an AWS
account through `sts:AssumeRole`; `sts:TagSession` is none of them, and the replacement, which
allows nothing, does not allow it either.
