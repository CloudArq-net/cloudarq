# 05 — a Deny names the outsider

`Accounts` allows the partner `111122223333` and the declared `444455556666`; `NotThePartner`
denies the partner. `aws:444455556666` is declared as yours.

**Expected.** The partner's population, let in by the Allow, has a proven fix that removes it from
statement 1's list; statement 2 is never edited, and the edit leaves it byte for byte. The Deny's
grant is refused and in no ring, and has no fix. The policy then opens on "Nothing outside your
company can assume this role."

**Why.** A principal is removed only from an Allow: removing one from a Deny lets more in, since
"An explicit deny in either of these policies overrides the allow."
(https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html). The
engine places a Deny in no ring and subtracts it from none, so the partner is still placed as let
in by the Allow, an upper bound; the fix shuts the Allow's way in, and every grant of the original
but the partner's, the Deny's among them, is left one for one.
