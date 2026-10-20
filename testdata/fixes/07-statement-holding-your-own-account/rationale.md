# 07 — the statement also lets your own account in

`PartnerAndUs` lists the partner's root and your own account's root, `444455556666`, declared as
yours.

**Expected.** The partner's fix is proven and removes the partner's string from the list, never the
statement: in statement 1 (`PartnerAndUs`), lines 4-9, remove
`"arn:aws:iam::111122223333:root"` from `Principal.AWS`. Your account's grant is left, and the policy
opens on "Nothing outside your company can assume this role." `--explain` gives your own account no
fix: the answer carries the one it would have were it not declared, so that withdrawing the
declaration says it again, and nothing tells you to shut your own account out.

**Why.** Removing the statement would take your own account's grant out with the partner's. The edit
removes the statement only when its Principal names nothing else, and check `grants` refuses any
edit that takes out a grant the principal did not make: every grant of the original but the
principal's must be left, one for one. The least edit never takes one out, so on a policy the
reader writes the check has nothing to refuse here; it is shown refusing an edit that removes the
whole statement by hand, taking out grant 3, which the partner's principal did not make, in
`TestTheChecksRefuseWhatTheyAreGiven` (`internal/report/fix_test.go`).
