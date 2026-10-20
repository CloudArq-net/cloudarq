# 10 — an outsider named by a condition, not a principal

`OneAccountThroughAStar` names `"*"` and lets in only callers whose `aws:PrincipalAccount` is
`111122223333`.

**Expected.** The account is a named outsider whose fix is unproven, check `leaf`: "No fix the
engine can prove yet: aws:111122223333 is let in by a condition, not by a principal the statement
names." The face of `"*"` for cloud services has its fix in words.

**Why.** The one edit the engine proves removes a principal that names the outsider. Here the
principal is `"*"`, which names everyone, and the account is named by the condition; removing `"*"`
is not that edit, and an edit to the condition is not one the engine proves yet.

> "Use this key to compare the account to which the requesting principal belongs with the account identifier that you specify in the policy." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html (`aws:PrincipalAccount`) · read 2026-09-23
