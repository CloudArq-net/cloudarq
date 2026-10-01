# 51 — a tenancy key spelled with a letter outside ASCII

`SubjectKeyWithALongS` spells the claim of its key `ſub`, with U+017F LATIN SMALL LETTER LONG S;
`ProviderKeyWithALongS` spells the provider before `repository_owner` with the same letter. The
document writes it as a JSON escape, so that the letter is visible, and because the escape is the
only form in which a policy carries it: AWS refuses a policy document that holds a character above
U+00FF as itself.

**Expected.**
- `SubjectKeyWithALongS` → **platform** (anyone on GitHub), unknown.
- `ProviderKeyWithALongS` → **platform** (anyone on GitHub), unknown.

**Why.** AWS documents that context key names are not case-sensitive and shows it on ASCII letters.
The long s folds to `s` and upper-cases to `S`, so under the widest folding AWS could apply the
first key is GitHub's `sub` and the second is GitHub's `repository_owner`; nothing read says
whether AWS folds it. The parser reads neither key as the claim, declares the constraint unread, and files the caveat
under the key as written. Each constraint names `acme` and would pin the grant to it if AWS reads
the key as the claim, so the grant is the platform with its state unknown. Read as a key of its own
spelling, the grant would be a clean *anyone on GitHub*, which asserts a reading of the key the
engine does not have.

> "Context key names are not case-sensitive." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html · read 2026-09-23
> "017F;LATIN SMALL LETTER LONG S;Ll;0;L;<compat> 0073;;;;N;;;0053;;0053" — https://www.unicode.org/Public/17.0.0/ucd/UnicodeData.txt (the thirteenth field is the simple upper-case mapping, U+0053 `S`) · read 2026-09-23
> "017F; C; 0073; # LATIN SMALL LETTER LONG S" — https://www.unicode.org/Public/17.0.0/ucd/CaseFolding.txt · read 2026-09-26
> "Policy documents can contain only the following Unicode characters: horizontal tab (U+0009), linefeed (U+000A), carriage return (U+000D), and characters in the range U+0020 to U+00FF." — https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html · read 2026-09-26
