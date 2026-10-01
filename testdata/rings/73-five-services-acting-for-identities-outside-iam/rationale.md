# 73 — five services that act for identities outside IAM, in one statement

A hand-written statement trusting the five services the engine's table lists, those it holds AWS's
sentences for on assuming a role for identities outside IAM, in an order that is not the engine's.

**Expected.** Five grants, one per service, each → **cloud services**, unknown, basis
`service-intermediary`, each note saying whom its service can assume a role for. The line says five
cloud services can assume the role and who can make them act is not read, which is true of each, and
cites every service's sentences, in the order of the line's grants, which is the engine's order of
the services and not the order written. The ring of anyone holds no grant and is **unknown** beside
the line.

**Why.** Each service in a Principal is its own grant, and each assumes the role for identities the
policy does not name. The line is the one place several such services' sentences are
cited together, so it is where an order that moved between runs would show; the answer must come out
byte for byte the same every time.

> "A service principal is an identifier for a service." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html · read 2026-09-27
> "You can use AWS Identity and Access Management Roles Anywhere to obtain temporary security credentials in IAM for workloads such as servers, containers, and applications that run outside of AWS." — https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html · read 2026-09-27
