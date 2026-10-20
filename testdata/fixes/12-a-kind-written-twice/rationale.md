# 12 — the member AWS written twice

`TwoCopies` writes `"AWS"` twice in its Principal: the partner's root, then the declared
`444455556666`.

**Expected.** Both fixes are unproven, check `placements`: "No fix the engine can prove yet: with
the principal removed, grant 2 would not be placed as it is now." (and grant 1 for the other).

**Why.** A JSON decoder keeps one copy of a member written twice, so each principal is read as an
upper bound: whether it is deployed is not known. Removing either copy leaves the other written
once, and its grant exact where it was an upper bound. That grant is then placed with another
certainty, and check `placements` holds every grant left to the same facts and the same reasons for being an
upper bound as its twin, so that the headline after the edit is the one the answer can say again
for any owners declared.
