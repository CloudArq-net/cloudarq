# 01 — a single principal is its statement's only one

Two statements: EC2 through `Instances`, and the account `111122223333` through `Partner`, by its
root ARN written as a string.

**Expected.** The account's population, a named outsider, has a proven fix: remove statement 2
(`Partner`, lines 10-15), whose Principal names nothing but `"arn:aws:iam::111122223333:root"`.
Grant 2 is taken out, no grant left lets `aws:111122223333` in by name, and the policy read again
opens on "ec2.amazonaws.com can assume this role." EC2's population on the line of cloud services
has its fix in words, unproven.

**Why.** The engine removes the least that takes the principal out. Removing the string alone would
leave `"Principal": {}`, a statement that names nobody, so the statement goes, with the comma before
it. The edited policy is read again with the same owners and every check holds: it reads with no
fault the original lacks, nothing names the account, EC2's grant is left as it was, and it is placed
as it was. The answer carries the edited policy's sha256 and never its text.
