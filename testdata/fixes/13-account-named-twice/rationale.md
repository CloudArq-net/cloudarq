# 13 — one account named twice

`Partner` lists `111122223333` twice, by its bare id and by its root ARN; `Instances` lets EC2 in.

**Expected.** Both of the account's fixes are unproven, check `owner`: "No fix the engine can prove
yet: grant 3 also lets aws:111122223333 in by name, so removing this principal does not shut it
out." (and grant 2 for the other).

**Why.** Check `owner` reads the edited policy again and refuses an edit after which a population
pinned to the account remains. "The account ARN and the shortened account ID behave the same way.
Both delegate permissions to the account" (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html),
so removing one spelling leaves the account let in by the other. The one edit is one principal, so
no single fix is proven here.
