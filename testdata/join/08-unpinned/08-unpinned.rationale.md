# 08 — no subject pin at all, and an effect that could not be read

Three grants:

- role `arn:aws:iam::111111111111:role/deploy` constrains only `aud` (conformance case 06,
  "unconstrained": every subject the issuer mints is admitted).
- role `arn:aws:iam::222222222222:role/deploy` admits `sub` like `repo:acme/*`, but its statement's
  `Effect` reads `allow`, which the AWS API would reject and the parser cannot read; the grant
  carries `EffectUnknown`, which the model says must be treated as possibly Allow
  (`internal/trust/grant.go`), so it pairs and casts doubt rather than vanishing.
- service-account `deploy@acme-prod.iam.gserviceaccount.com` constrains only `aud`.

With `aud` set aside the first role and the service account admit everything, and their overlap
is `{}`, the set of every identity; the empty token witnesses it, since an absent claim
satisfies only an unconstrained one, and both sides admit the empty token. The sentence says
"any identity" and offers no example, because there is nothing to add. `witness` renders as `{}`,
not `null`: an example was found, and it is the empty token.

The second role overlaps each of the others on `{sub=like:"repo:acme/*"}`, with the example
`repo:acme/`, but both of its links are `Indeterminate` because its effect could not be read. Its
grant reference renders `"effect": "Unknown"`, the effect as the parser left it, where every
other reference in the corpus renders `"effect": "Allow"`.

Links, sorted by target kind then id:

> Identities admitted by role arn:aws:iam::111111111111:role/deploy may also be admitted by role arn:aws:iam::222222222222:role/deploy from https://token.actions.githubusercontent.com; the effect of the statement granting role arn:aws:iam::222222222222:role/deploy could not be read.

> Identities admitted by role arn:aws:iam::111111111111:role/deploy are also admitted by service-account deploy@acme-prod.iam.gserviceaccount.com: both admit any identity from https://token.actions.githubusercontent.com.

> Identities admitted by role arn:aws:iam::222222222222:role/deploy may also be admitted by service-account deploy@acme-prod.iam.gserviceaccount.com from https://token.actions.githubusercontent.com; the effect of the statement granting role arn:aws:iam::222222222222:role/deploy could not be read.
