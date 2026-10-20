# 11 — the partner is the policy's only principal

`Partner` is the policy's only statement, and the partner's root is its only principal.

**Expected.** The fix is proven, and it replaces the whole policy (`removes` is `policy`): "Replace
the whole trust policy with one that lets no one in: statement 1 ("Partner"), lines 4-9, is its only
statement, the only principal it names is "arn:aws:iam::111122223333:root", and IAM refuses a trust
policy with no statement." It goes on: "This stops aws:111122223333 from getting in. If you still
work with them, don't apply it. Anyone already in keeps their access until their session ends,
which can take hours. The role's "Revoke active sessions" ends those sessions now. Deleting the
role instead also removes what its permissions allow." Grant 1 is taken out, no grant left lets
anyone in, and the replacement opens on "Nothing outside your company can assume this role."
The answer carries the replacement's sha256, never its text, which is:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyEveryone",
      "Effect": "Deny",
      "Principal": {"AWS": "*"},
      "Action": "sts:AssumeRole"
    }
  ]
}
```

**Why.** Removing the statement would leave `"Statement": []`, and IAM refuses a trust policy whose
Statement is empty: `MalformedPolicyDocument: Could not parse the policy: Statement is empty!`. The
least edit that shuts the partner out is then a policy whose one statement lets no one in. It
denies `sts:AssumeRole`, the action the engine reads an AWS principal assuming a role through, to
every AWS principal, and keeps the original's `Version`; with no Allow statement at all, it lets no
one in through any action. The engine reads the replacement again with the same owners and offers
it only when the checks hold: it reads with no fault the original lacks but those of its own Deny,
which only refuses; every grant it makes is a Deny, placed in no ring, so no population of the
partner, or of anyone, is left; and every grant of the original goes with the partner's principal.

Replacing the trust policy stops anyone from assuming the role again and does not end what is
already issued: "Temporary
security credentials are valid until they expire." Ending them is a step of its own: "For IAM role
sessions, you can revoke the role's temporary security credentials to force all users assuming the
role to reauthenticate and request new credentials."
(https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_disable-perms.html).
The IAM console's button for that is "Revoke active sessions"
(https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html). The words
give no bound on how long that lasts. Credentials still valid can be sent to the federation
endpoint for a console session, a call that does not read the trust policy, and the console
session's SessionDuration "is separate from the duration of the temporary credentials": at most
12 hours from sign-in, and less than the role's maximum session duration. So a console session
made just before the credentials expire outlasts them; "you can immediately disable the active
console sessions for any role by choosing Revoke Sessions"
(https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html).
