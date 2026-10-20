# 06 — NotPrincipal

`EveryoneButThePartner` allows every principal but the partner's account, through `NotPrincipal`.

**Expected.** The statement's grant lands with anyone: the parser reads that "NotPrincipal is not
supported in a role trust policy and names who is excluded rather than who is admitted, so who the
statement admits is not known". Its fix is unproven, check `principal`: "No fix the engine can prove
yet: no principal the engine reads lets this way in, and so far it removes only a principal written
under Principal.AWS, other than "*"." No edit touches the statement.

**Why.** Under `NotPrincipal` a principal is one the statement does not admit, so removing it widens
who an Allow lets in, the one direction a fix may never move. The engine's edit refuses a principal
written under `NotPrincipal`, and refuses any principal of a statement that writes `NotPrincipal`
beside `Principal`, with why; those refusals are in `internal/parse/aws/edit_test.go`.
