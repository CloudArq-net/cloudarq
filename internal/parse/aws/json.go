package aws

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// value is one JSON value and where it sits in the source. Object members
// stay in document order with duplicates intact: the decoder that would
// collapse a repeated key is the one thing this parser must not be, because
// a duplicate condition key is a fact about the deployed policy and the
// Terraform provider already erases it upstream of us.
type value struct {
	kind    kind
	text    string   // the decoded string, or a number's literal text
	boolean bool     // kindBool only
	members []member // kindObject, in document order, duplicates kept
	items   []*value // kindArray
	// start and end are byte offsets into source, [start, end): the value's
	// own bytes, no surrounding whitespace or separators, escapes as written.
	// Every value of one tree shares the one source, so a value can quote
	// itself without the document being threaded to it.
	source     []byte
	start, end int
}

// bytes is the value's own text, as the customer wrote it.
func (v *value) bytes() []byte { return v.source[v.start:v.end] }

type member struct {
	name  string
	value *value
}

// kind names the JSON type, for the total mappings in policy.go and for
// the sentence an anomaly prints when a member has the wrong one.
type kind int

const (
	kindNull kind = iota
	kindBool
	kindNumber
	kindString
	kindArray
	kindObject
)

func (k kind) String() string {
	return [...]string{"null", "a boolean", "a number", "a string", "a list", "an object"}[k]
}

// parseTree decodes exactly one JSON value from raw. Anything else is an
// error: empty input, a second value after the first, trailing bytes, a byte
// order mark, invalid UTF-8, a lone UTF-16 surrogate escape. The decoder is
// a stream decoder that would happily stop at the first value's closing
// brace, so the end of the input is checked deliberately; a second policy
// concatenated after the first must not vanish.
//
// Invalid UTF-8 is refused rather than decoded, because the decoder would
// replace each bad byte with U+FFFD and an Exact built from that value
// would not be the customer's value. A \uD800 escape with no low surrogate
// after it decodes to U+FFFD the same silent way, and is refused for the
// same reason.
func parseTree(raw []byte) (*value, error) {
	if at := firstInvalidUTF8(raw); at < len(raw) {
		return nil, fmt.Errorf("not valid UTF-8 at byte %d", at)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, errors.New("empty input")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	r := &reader{dec: dec, raw: raw}
	root, err := r.readValue()
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("a second value")
		}
		return nil, fmt.Errorf("after the document: %w", err)
	}
	return root, nil
}

func firstInvalidUTF8(raw []byte) int {
	for i := 0; i < len(raw); {
		r, size := utf8.DecodeRune(raw[i:])
		if r == utf8.RuneError && size == 1 {
			return i
		}
		i += size
	}
	return len(raw)
}

// reader walks the token stream and recovers each token's byte range. The
// decoder reports only where a token ends; where it begins is the first
// byte after the previous token that is not whitespace, ':' or ','. In a
// well-formed stream nothing else can sit between two tokens, and no token
// starts with one of those bytes, so the scan lands exactly on the token.
//
// The stream alone says where an object or an array ends: its closing
// delimiter arrives as a token. More is not consulted, because the two
// implementations of the decoder disagree about what it reports at a
// truncated end, and a reader that trusted it would have one truncation
// path per implementation.
type reader struct {
	dec   *json.Decoder
	raw   []byte
	depth int // objects and arrays open around the token being read
}

// maxNesting bounds how deep an object or an array may sit. The reader
// recurses once per level, so its stack is bounded by this and by nothing
// the decoder promises: Go 1.24's Decoder.Token has no depth limit, and a
// document nested a few million levels deep overflowed the goroutine
// stack, a fatal error no recover can catch; later releases refuse at
// 10,000. The bound sits well below that so the answer is the same on
// every toolchain, and far above the six levels the IAM grammar nests.
const maxNesting = 1000

// next returns the token a value or a member needs, so the end of the input
// here is always premature: the decoder reports a bare EOF inside an open
// object, and a caller reading that as "end of document" would accept a
// truncated policy.
func (r *reader) next() (tok json.Token, start, end int, err error) {
	start = int(r.dec.InputOffset())
	tok, err = r.dec.Token()
	if errors.Is(err, io.EOF) {
		return nil, 0, 0, io.ErrUnexpectedEOF
	}
	if err != nil {
		return nil, 0, 0, err
	}
	end = int(r.dec.InputOffset())
	for start < end && isBetweenTokens(r.raw[start]) {
		start++
	}
	if _, isString := tok.(string); isString {
		if err := loneSurrogate(r.raw, start, end); err != nil {
			return nil, 0, 0, err
		}
	}
	return tok, start, end, nil
}

// loneSurrogate refuses a string literal, at raw[start:end], holding a
// \u escape in the UTF-16 surrogate range that is not half of a pair. The
// decoder has already accepted the literal, so every escape in it is well
// formed and the scan needs no error path of its own: a backslash starts
// an escape, a \u escape is followed by four hex digits, and anything else
// is text.
func loneSurrogate(raw []byte, start, end int) error {
	for i := start; i < end; i++ {
		if raw[i] != '\\' {
			continue
		}
		if raw[i+1] != 'u' {
			i++ // the escaped character, which may be a backslash
			continue
		}
		escape := i
		code := hex4(raw[escape+2:])
		i = escape + 5 // the last hex digit
		switch {
		case code < 0xD800 || code > 0xDFFF:
		case code < 0xDC00 && isLowSurrogateEscape(raw[i+1:]):
			i += 6
		default:
			return fmt.Errorf("lone UTF-16 surrogate escape %s at byte %d", raw[escape:i+1], escape)
		}
	}
	return nil
}

// isLowSurrogateEscape reports whether s starts with a \u escape in the
// low surrogate range, the second half a high surrogate needs.
func isLowSurrogateEscape(s []byte) bool {
	if len(s) < 6 || s[0] != '\\' || s[1] != 'u' {
		return false
	}
	code := hex4(s[2:])
	return 0xDC00 <= code && code <= 0xDFFF
}

// hex4 reads the four hex digits of a \u escape the decoder has accepted.
func hex4(s []byte) rune {
	var code rune
	for _, c := range s[:4] {
		code <<= 4
		switch {
		case '0' <= c && c <= '9':
			code |= rune(c - '0')
		case 'a' <= c && c <= 'f':
			code |= rune(c-'a') + 10
		default:
			code |= rune(c-'A') + 10
		}
	}
	return code
}

func isBetweenTokens(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == ':' || b == ','
}

func (r *reader) readValue() (*value, error) {
	tok, start, end, err := r.next()
	if err != nil {
		return nil, err
	}
	return r.valueOf(tok, start, end)
}

// valueOf builds the value a token begins. The decoder validates nesting,
// so a delimiter here opens an object or an array; the closing ones are
// consumed by readObject and readArray and never reach a value position.
func (r *reader) valueOf(tok json.Token, start, end int) (*value, error) {
	switch t := tok.(type) {
	case json.Delim:
		if r.depth == maxNesting {
			return nil, fmt.Errorf("nested more than %d levels deep at byte %d", maxNesting, start)
		}
		r.depth++
		defer func() { r.depth-- }()
		if t == '{' {
			return r.readObject(start)
		}
		return r.readArray(start)
	case string:
		return &value{kind: kindString, text: t, source: r.raw, start: start, end: end}, nil
	case json.Number:
		return &value{kind: kindNumber, text: t.String(), source: r.raw, start: start, end: end}, nil
	case bool:
		return &value{kind: kindBool, boolean: t, source: r.raw, start: start, end: end}, nil
	}
	return &value{kind: kindNull, source: r.raw, start: start, end: end}, nil
}

func (r *reader) readObject(start int) (*value, error) {
	v := &value{kind: kindObject, source: r.raw, start: start}
	for {
		tok, _, end, err := r.next()
		if err != nil {
			return nil, err
		}
		if tok == json.Delim('}') {
			v.end = end
			return v, nil
		}
		val, err := r.readValue()
		if err != nil {
			return nil, err
		}
		// Object keys are always strings in a stream the decoder accepts.
		v.members = append(v.members, member{name: tok.(string), value: val})
	}
}

func (r *reader) readArray(start int) (*value, error) {
	v := &value{kind: kindArray, source: r.raw, start: start}
	for {
		tok, itemStart, end, err := r.next()
		if err != nil {
			return nil, err
		}
		if tok == json.Delim(']') {
			v.end = end
			return v, nil
		}
		item, err := r.valueOf(tok, itemStart, end)
		if err != nil {
			return nil, err
		}
		v.items = append(v.items, item)
	}
}
