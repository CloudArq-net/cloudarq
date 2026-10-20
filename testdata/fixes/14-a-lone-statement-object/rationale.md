# 14 — a vendor's role, its one statement written as an object

`Statement` is one object, not a list: `Vendor` lets the role `vendor-audit` in account
`111122223333` in, on condition that `sts:ExternalId` is `a1b2c3`. This is the shape of a role made
for one vendor alone.

**Expected.** The vendor's fix is proven and replaces the whole policy (`removes` is `policy`), as in
case 11: "Replace the whole trust policy with one that lets no one in: statement 1 ("Vendor"), lines
3-9, is its only statement, the only principal it names is
"arn:aws:iam::111122223333:role/vendor-audit", and IAM refuses a trust policy with no statement."
The replacement keeps `"Version": "2012-10-17"`, and opens on "Nothing outside your company can
assume this role."

**Why.** Removing the statement here removes the `Statement` member itself, which leaves a document
with no statement at all; the IAM policy grammar requires one, and IAM refuses a trust policy whose
Statement is empty. The condition does not change the edit: the statement goes, or the policy is
replaced, whatever it is conditioned on, and the replacement is proven by the checks of case 11.
