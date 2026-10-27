# 04 — an account Segment publishes on two pages

The policy trusts `arn:aws:iam::595280932656:root` on condition that `sts:ExternalId` is one
value.

**Expected.** Grant 1 → **outsider**, exact. The owner carries `listed`: the vendor `Segment
(Twilio)` and two uses, each with its own source, in the list's order. The sentence names the
vendor once, as it does for an account on one page: "aws:595280932656, which Segment (Twilio)
publishes as its own, can assume this role and is not declared as yours." --explain gives each
page on a line of its own, with its use.

**Why.** `internal/vendors/aws-accounts.json` holds `595280932656` in `aws` as Segment (Twilio)'s,
from two pages, each saying what the account is used for.
