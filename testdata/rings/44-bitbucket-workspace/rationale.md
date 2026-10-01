# 44 — a Bitbucket workspace, whose pipelines are not shown to be its owner's alone

A per-tenant issuer, whose URL names the workspace: Bitbucket's `tenant_membership` is `unverified`
in census v0.2.0.

**Expected.** `BitbucketWorkspace` → **platform** (anyone on Bitbucket), unknown.

**Why.** The issuer URL names the workspace. Who can run a pipeline in a workspace's repositories,
a pull request from a fork among them, is not established by any sentence the census read, so the
workspace is not shown to control who obtains its tokens: the grant is the platform, unknown, and
not a named outsider. The workspace id is a name that can be renamed, which the census records
beside it.

The platform is named where the workspace's people hold their accounts, Bitbucket, not by the
product that mints the tokens: the census records it with its sentence (census v0.2.0).

> ""iss": "https://api.bitbucket.org/2.0/workspaces/bbcitest/pipelines-config/identity/oidc"" — https://support.atlassian.com/bitbucket-cloud/docs/deploy-on-aws-using-bitbucket-pipelines-openid-connect/ · read 2026-09-23 (recorded in the census, `match`)
> "You must be using Pipelines in your repository to integrate OpenID Connect." — https://support.atlassian.com/bitbucket-cloud/docs/integrate-pipelines-with-resource-servers-using-oidc/ · read 2026-09-23 (recorded in the census as context to `tenant_membership`)
> "For example, if you rename your workspace ID from johnc to jcitizen, the repository previously available at http://bitbucket.org/johnc/repo is accessed as http://bitbucket.org/jcitizen/repo after renaming." — https://support.atlassian.com/bitbucket-cloud/docs/change-a-workspace-id/ · read 2026-09-23
> "To join or create a workspace, you need an individual Bitbucket account." — https://support.atlassian.com/bitbucket-cloud/docs/create-your-workspace/ · read 2026-09-24 (recorded in the census, `accounts`)
