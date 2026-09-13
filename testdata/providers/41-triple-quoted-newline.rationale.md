# 41 — a triple-quoted literal holding a carriage return

Hand-written fixture, 2026-09-13.

## Document

`assertion.sub == '''deploy<CR><LF>main'''` (the JSON escapes `\r\n`; the
CEL text holds a real carriage return and line feed between the triple
quotes).

## Expected

`{aud="…/providers/github"}` with `sub` Unknown: inexact, a caveat on
`sub`, an `unmodelled-construct` anomaly whose Construct is `carriage
return` and whose sentence says that cel-go and cel-cpp read the carriage
return as a line feed and the language definition does not say.

## Why

The language definition: "Triple-quoted strings may contain newlines." It
says nothing about which newline a literal then holds. cel-go's
`parser/unescape.go` begins `unescape` with a replacer of `"\r\n"` and
`"\r"` by `"\n"` applied to every literal, raw ones included, and
cel-cpp's `internal/strings.cc` does the same in `UnescapeInternal` ("All
types of newlines in different platforms i.e. '\r', '\n', '\r\n' are
replaced with '\n'"). Google's evaluator is not one this parser can read.
An Exact on `deploy\nmain` is narrower than Google if Google keeps the
carriage return; an Exact on `deploy\r\nmain` is narrower if Google reads
it as the two implementations do. Neither can be claimed, so the claim is
Unknown, declared, and the literal is read as the implementations read it
in case a later unit can settle the question. A single-quoted literal
cannot hold a newline at all ("can contain any unescaped character except
the delimiter or newlines (either CR or LF)"), and an escaped `\r` is
settled by the definition and read exactly.

## Sources

- https://github.com/google/cel-spec/blob/master/doc/langdef.md (String and Bytes Values)
- https://github.com/google/cel-go/blob/v0.32.0/parser/unescape.go (`newlineNormalizer`)
- https://github.com/google/cel-cpp/blob/master/internal/strings.cc (`UnescapeInternal`)
