# 05 — a listed account beside one no vendor publishes

One statement trusts `arn:aws:iam::464622532012:root` and `arn:aws:iam::111122223333:root`.

**Expected.** Two grants, both → **outsider**, exact. Only the owner `464622532012` carries
`listed`. The ring names the account the vendor publishes first and the vendor right after it:
"aws:464622532012, which Datadog publishes as its own, and aws:111122223333 can assume this role
and are not declared as yours." Grant 1's *who* is as it is today, and grant 2's names Datadog.

**Why.** The list holds `464622532012` in `aws` and does not hold `111122223333`. Named after
both accounts, the vendor would read as said of both, and `111122223333` as Datadog's.
