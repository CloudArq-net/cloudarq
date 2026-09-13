# 14 — a raw string literal

Hand-written fixture, 2026-09-13.

## Document

`assertion.sub == r'repo:acme\infra'` (the JSON escapes the backslash once;
the CEL text holds one backslash).

## Expected

`{aud="…/providers/github", sub="repo:acme\\infra"}`, exact: the value
holds a literal backslash.

## Why

CEL: "If preceded by an `r` or `R` character, the string is a _raw_ string and
does not interpret escape sequences." The value is therefore the characters
between the quotes as written, backslash included, and equality on it is
exact. The Pass 1 table listed raw strings beside bytes literals as Unknown;
bytes are not strings and stay Unknown (a `b'…'` literal compared to a claim
is a type error in CEL), but a raw string is a string whose value CEL
defines without ambiguity, so it is read exactly. Reading it is never
narrower than Google.

## Sources

- https://github.com/google/cel-spec/blob/master/doc/langdef.md (STRING_LIT, "raw string")
