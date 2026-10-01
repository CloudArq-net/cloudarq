# 06 — an owner id written after a wildcard

The trap of an owner id found mid-string.

**Expected.** `OwnerIDAfterAWildcard` → **platform** (anyone on GitHub), exact.

**Why.** The literal prefix of `repo:*@123456/*` is `repo:`: it ends at the first wildcard, before
any owner part, so it pins nothing whatever follows. The id found later in the pattern is not a
pin: a branch named `x@123456/y` in anyone's repository puts `@123456/` mid-subject, as in
`repo:attacker/r:ref:refs/heads/x@123456/y`, and the pattern admits it. Git allows the slash and the
`@`, and GitHub adds only two restrictions, neither of which excludes the name:

> "They can include slash / for hierarchical (directory) grouping" — https://git-scm.com/docs/git-check-ref-format · read 2026-09-23
> "They cannot contain a sequence @{." — https://git-scm.com/docs/git-check-ref-format · read 2026-09-23
> "They cannot be the single character @." — https://git-scm.com/docs/git-check-ref-format · read 2026-09-23
> "No names beginning with `refs/`, to prevent confusion with the full name of Git refs." — https://docs.github.com/en/get-started/using-git/dealing-with-special-characters-in-branch-and-tag-names · read 2026-09-23
> "Case-sensitive matching. The values can include multi-character match wildcards (*) and single-character match wildcards (?) anywhere in the string." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html (`StringLike`) · read 2026-09-23
