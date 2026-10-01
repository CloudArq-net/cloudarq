# 42 — principals the parser does not model

A principal whose kind of identity the engine cannot say is placed outward.

**Expected.**
- `S3CanonicalUser` → **anyone**, unknown: the principal is not one the parser models.
- `BucketAsPrincipal` → **anyone**, unknown: the principal is not one the parser models.
- `RoleAsFederatedProvider` → **anyone**, unknown: its grant names no issuer, and a principal the
  parser could not read may name any identity.

**Why.** AWS lists the principals a policy can name, and a role trust policy that names one of
these three names none of them in a form the parser models. The parser files a CanonicalUser and an
ARN of another service under the AWS issuer, because they sit under a key that names AWS principals
or beside one, but it cannot say what kind of identity either stands for, and it lets a
CanonicalUser assume the role through every action, web identity and SAML included. So the AWS
issuer's population, anyone with an AWS account, is not shown to hold whoever can present a
credential these grants admit, and the nearest ring that is shown to is *anyone*. The parser says so
through `Statement.ModelsPrincipalOf`, never through the sentence it writes about the principal. A
role's ARN under `Federated` names no identity provider, so the parser gives its grant no issuer, and
it is anyone's for the same reason.

What IAM does with each document when it is saved is not read here; the engine answers for the
document as written, and the question stays open until IAM's behaviour is read.

> "You can specify any of the following principals in a policy:" — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html (the list that follows: the AWS account and root user, IAM roles, role sessions, IAM users, federated user principals, AWS services, all principals) · read 2026-09-23
> "Some AWS services support additional options for specifying an account principal." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html · read 2026-09-23
> "For example, Amazon S3 lets you specify a canonical user ID using the following format:" — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html · read 2026-09-23
> "The principal_map element in Amazon S3 bucket policies can include the CanonicalUser ID. Most resource-based policies do not support this mapping." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html · read 2026-09-23
> "An OIDC federated principal can represent an OIDC IDP in your AWS account, or the 4 built in identity providers: Login with Amazon, Google, Facebook, and Amazon Cognito." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html · read 2026-09-23
> "SAML IDPs used in a role trust policy must be in the same account that the role is in." — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_saml.html · read 2026-09-23
