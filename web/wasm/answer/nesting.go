package answer

import "fmt"

// MaxDocumentNesting and MaxTokenNesting bound how deep a document or a
// token may nest. The parser, the layout reader and the token reader each
// recurse once per level, on a stack the WebAssembly build fixes at link
// time (web/wasm/target.json, 1 MB), and past that stack the engine traps
// rather than answers: a trap kills the instance, so it is the entry's job
// to refuse depth before any reader sees a byte, in a sentence.
//
// The bounds come from where that build traps with every bound lifted
// (this file's and the parser's), measured in node on 2026-09-13 by binary
// search over a fresh instance per probe: a document of objects trapped at
// 2173 levels, of arrays at 2607, of arrays holding objects at 2370, of
// objects inside a condition value at 2169 and of arrays there at 2602; a
// token's claim trapped at 1162 levels for arrays, objects and arrays
// holding objects alike. Each bound is under half its shallowest trap, and
// the IAM grammar nests six levels.
const (
	MaxDocumentNesting = 1000
	MaxTokenNesting    = 500
)

// nesting refuses text nested deeper than limit, naming what it is. The
// scan is one pass over the bytes and never descends: a bracket inside a
// string is text, and everything else that may be wrong with the bytes is
// left to the reader that follows, which says it in its own words. The
// depth named is the text's whole depth, and the byte is where the first
// level past the bound opens.
func nesting(text []byte, limit int, what string) error {
	depth, deepest, past := 0, 0, -1
	inString, escaped := false, false
	for i, b := range text {
		switch {
		case inString:
			switch {
			case escaped:
				escaped = false
			case b == '\\':
				escaped = true
			case b == '"':
				inString = false
			}
		case b == '"':
			inString = true
		case b == '{' || b == '[':
			depth++
			if depth > deepest {
				deepest = depth
			}
			if depth > limit && past < 0 {
				past = i
			}
		case b == '}' || b == ']':
			depth--
		}
	}
	if past < 0 {
		return nil
	}
	return fmt.Errorf("the %s is nested %d levels deep; the engine reads up to %d levels, and level %d opens at byte %d", what, deepest, limit, limit+1, past)
}
