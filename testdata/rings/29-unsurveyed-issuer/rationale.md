# 29 — an issuer the census has not surveyed

A trap: an issuer the census has not surveyed is *anyone*, unknown.

**Expected.** `UnsurveyedIssuer` → **anyone**, unknown.

**Why.** Nothing establishes that `https://ci.example.com` issues tokens only to people with an
account, so the nearest ring guaranteed to hold everyone it can issue a token to is *anyone*. The
host is reserved for documentation and stands for any issuer the census lacks. Declaring it cannot
move it: owning an issuer does not bound who it issues to.

> "By default, any user visiting your GitLab domain can create an account." — https://docs.gitlab.com/administration/settings/sign_up_restrictions/ (an issuer's owner and its population are two different things) · read 2026-09-23
