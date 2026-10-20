# 03 — a principal in a list of one and as a string

Two statements, each naming a service beside one account: `InAList` writes
`"AWS": ["arn:aws:iam::111122223333:root"]` after its service, and `AsAString` writes
`"AWS": "777788889999"` before its service.

**Expected.** Both accounts are named outsiders with proven fixes, and both edits remove the member
`Principal.AWS`, which names only that account: the list of one goes whole, as the string does, and
the service beside it stays. After either edit the policy opens on "A named outsider can assume this
role; so can cloud services."

**Why.** A list of one and a string name the same one principal, and removing the string from the
list would leave `"AWS": []`, a list the IAM grammar does not allow, which the reader would call a
fault the original does not have. So the member goes, with its comma, and the Principal keeps its
other member. The offsets the edit is made at are the reader's own, for the list item and the string
alike.
