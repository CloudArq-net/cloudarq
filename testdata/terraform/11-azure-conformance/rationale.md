# 11 — the conformance corpus as azuread credentials

**Hand-written to the documented format** (format 1.2, from the corpus by a script, the values
copied out of `testdata/grants/*/azure.json`): one
`azuread_application_federated_identity_credential.conformance["NN"]` per case a classic
credential can state, with the shapes of case 03.

Cases 01 and 04 have a `subject`; 03, 05 and 07 are flexible credentials
(`claimsMatchingExpression`), which the azuread provider cannot express, its schema at main
having `subject` Required and no expression argument; 02 and 06 have no Azure document in the
corpus at all. `TestDifferentialConformance` holds the reader's grants for 01 and 04 to what
`azure.ParseFederatedCredential` makes of the corpus documents, and asserts that the plan
states nothing for the five others, so that what Terraform's Azure provider cannot say is a
fact the tests state rather than a gap they pass over.

Source: the azuread resource's schema at main (`scratchpad/critic-a/azuread-fic.go`, lines
45-100) and its documentation, fetched 2026-09-14.
