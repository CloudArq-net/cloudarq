# 49 — assume actions spelled with a letter outside ASCII

Each statement spells the assume action its principal needs with letters outside ASCII whose case
mappings give ASCII ones: U+0131 LATIN SMALL LETTER DOTLESS I, which upper-cases to `I`; U+017F
LATIN SMALL LETTER LONG S, which upper-cases to `S`; and U+0130 LATIN CAPITAL LETTER I WITH DOT
ABOVE, which lower-cases to `i`. The document writes each as a JSON escape, so that the letter is
visible.

**Expected.**
- `GitHubThroughADotlessI` → **platform**, unknown: anyone on GitHub Actions, if the action is the
  web identity one.
- `AnyoneThroughALongS` → **anyone**, unknown, through the face of `"*"` that names no issuer. Its
  AWS face admits **nobody**: no case mapping makes the action `sts:AssumeRole`.
- `AnySAMLThroughADotlessI` → **anyone**, unknown, through the same face; its AWS face admits
  **nobody**.
- `AccountThroughALongS` → **outsider**, exact: account `111122223333`.
- `SAMLProviderThroughADotlessI` → **SAML sign-ins**, unknown.
- `ServiceThroughALongS` → **Cloud services**, unknown.
- `CognitoThroughADottedCapitalI` → **anyone**, unknown: an identity pool mints tokens to guests.

**Why.** AWS matches action names regardless of case and does not say which letters that reaches.
Java's `String.equalsIgnoreCase` equates each of these spellings with the ASCII one (run under JDK
21.0.4 and 23.0.1), and Unicode's case mappings give each letter the ASCII one it stands for;
nothing read for this case says how IAM compares action names beyond ASCII. Read as letters of
their own, the actions named no assume action and every grant admitted nobody, exactly, for
statements that may let in anyone on GitHub, anyone at all, an account, SAML providers' sign-ins, a
service and an identity pool's guests. That is the one direction the engine must never err in.

The engine reads such an action as the assume action it may be and declares the grant's set an
upper bound, so each grant lands where the ASCII spelling's does, or further out:
- The GitHub grant, which no condition pins, is unknown rather than exact: whether it admits
  anyone rests on the folding nobody documented.
- The account's grant stays exact: if the statement lets anyone in, it is that account.
- The face of `"*"` that names no issuer reads every issuer whenever an action holds such a
  letter. Which assume action the letter spells is the fact nobody documented. For
  `AnySAMLThroughADotlessI` that is further out than the ASCII spelling's place, the SAML
  providers of the role's own account.

Whether IAM stores such a document, and how its matcher folds action names, was not tested against
IAM; the engine answers for the document as written.

> "The prefix and the action name are case insensitive." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html · read 2026-09-23
> "0131;LATIN SMALL LETTER DOTLESS I;Ll;0;L;;;;;N;;;0049;;0049" — https://www.unicode.org/Public/17.0.0/ucd/UnicodeData.txt (the thirteenth field is the simple upper-case mapping, U+0049 `I`) · read 2026-09-23
> "017F;LATIN SMALL LETTER LONG S;Ll;0;L;<compat> 0073;;;;N;;;0053;;0053" — https://www.unicode.org/Public/17.0.0/ucd/UnicodeData.txt (the simple upper-case mapping is U+0053 `S`) · read 2026-09-23
> "0130;LATIN CAPITAL LETTER I WITH DOT ABOVE;Lu;0;L;0049 0307;;;;N;LATIN CAPITAL LETTER I DOT;;;0069;" — https://www.unicode.org/Public/17.0.0/ucd/UnicodeData.txt (the simple lower-case mapping is U+0069 `i`) · read 2026-09-23
