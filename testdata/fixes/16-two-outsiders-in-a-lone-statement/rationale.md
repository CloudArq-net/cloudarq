# 16 — two vendors in the one statement

`Statement` is one object, `Vendors`, which lists two accounts under `AWS`: `111122223333` by its
root ARN and `777788889999` by its bare id.

**Expected.** Each account's fix is proven and removes its string from `Principal.AWS` (`removes` is
`principal`), never the policy: in statement 1 (`Vendors`), lines 3-8, remove
`"arn:aws:iam::111122223333:root"`, or remove `"777788889999"`. After either edit the policy opens on
"A named outsider can assume this role.", since the other account is still let in.

**Why.** A policy is replaced only when removing the principal would leave it no statement. Here the
least edit removes one string from a list that names another, so the statement, and the other
account's way in, stay as written. Each fix shuts out the account it names and says nothing of the
other.
