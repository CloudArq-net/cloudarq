# 15 — Facebook as a built-in provider

One of the four identity providers AWS builds in: Facebook.

**Expected.** `FacebookApp` → **anyone**, unknown.

**Why.** Facebook issues several kinds of token and one of them is embedded in apps and not secret;
which kinds STS accepts as a `graph.facebook.com` OAuth 2.0 access token is not documented. Census v0.2.0
therefore records `anonymous_tokens` as `unverified`, and an unverified fact reads the cautious
way, as *anyone*.

> "Client tokens identify your app when calling app-level APIs from native or desktop apps. Because client tokens are embedded in apps, they are not secret." — https://developers.facebook.com/docs/facebook-login/guides/access-tokens · read 2026-09-23
> "Currently `www.amazon.com` and `graph.facebook.com` are the only supported identity providers for OAuth 2.0 access tokens." — https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html · read 2026-09-23
