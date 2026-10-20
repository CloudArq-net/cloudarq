# 02 — one principal of several in a list

One statement, `Partners`, lists two accounts under `AWS`: `111122223333` by its root ARN and
`777788889999` by its bare id, one per line.

**Expected.** Each account is a named outsider with its own proven fix: remove its string from
`Principal.AWS`, with the comma beside it, leaving the other in the list. After either edit the
policy opens on "A named outsider can assume this role.", since the other account is still let in.

**Why.** A list that names others keeps them: the edit cuts one item and its separator, up to the
start of the next item, or from the end of the one before it for the last, so the lines around it
stay as written. The fix shuts out the account it names and says nothing of the other, which keeps
its own fix. Both spellings name the account: "The account ARN and the shortened account ID behave
the same way. Both delegate permissions to the account" (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html).
