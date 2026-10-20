# 17 — your own account beside a vendor's, in the one statement

`Statement` is one object, `VendorAndUs`, which lists the vendor's root, `111122223333`, and your own
account's root, `444455556666`, declared as yours.

**Expected.** The vendor's fix is proven and removes its string from `Principal.AWS` (`removes` is
`principal`): in statement 1 (`VendorAndUs`), lines 3-8, remove `"arn:aws:iam::111122223333:root"`.
Your account's grant is left, and the policy opens on "Nothing outside your company can assume this
role." `--explain` gives your own account no fix: the answer carries the one it would have were it
not declared, as in case 07.

**Why.** The least edit that shuts the vendor out leaves your own account in the statement, so the
policy keeps a statement and is never replaced. Replacing it would shut your own account out as
well, which the edit for one principal never does.
