# 22 — a subject led by `job_workflow_ref:`

A trap: a subject that looks as if it names a tenant and does not.

**Expected.** `CalledWorkflow` → **platform** (anyone on GitHub), exact.

**Why.** `job_workflow_ref` names the called reusable workflow, not the repository whose workflow
called it. A public reusable workflow can be called from any repository, and a repository chooses its
own subject template, so any repository can mint `sub` = `job_workflow_ref:acme/deploy/…`. A subject
led by `job_workflow_ref:` never pins.

> "If that job is part of a reusable workflow, the token will include the standard claims that contain information about the calling workflow, and will also include a custom claim called `job_workflow_ref` that contains information about the called workflow." — https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-with-reusable-workflows · read 2026-09-23
> "The called workflow is stored in a public repository, and your organization allows you to use public reusable workflows." — https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations · read 2026-09-23
> "Customizing the claims results in a new format for the entire `sub` claim, which replaces the default predefined `sub` format in the token described in" — https://docs.github.com/en/actions/reference/security/oidc · read 2026-09-23
