# 30 — proto field names

Hand-written fixture, 2026-09-13.

## Document

Every member spelt as its proto field name: `attribute_condition`,
`attribute_mapping`, `display_name`, `issuer_uri`, `allowed_audiences`.

## Expected

`{aud="…/providers/github", sub="repo:acme/infra:ref:refs/heads/main"}`,
exact, no anomaly: the same grant as case 01.

## Why

The protobuf JSON mapping: "Parsers accept both the lowerCamelCase name
and the original proto field name." A reader that knew only the camelCase
names would report this document as everything from the issuer, exact and
with no anomaly, on a spelling Google's own API honours: silence read as
clean. Both spellings are read; a document that writes both spellings of
one member has written that member twice, and case 21's rule applies.

## Sources

- https://protobuf.dev/programming-guides/json/ ("Parsers accept both the lowerCamelCase name and the original proto field name.")
