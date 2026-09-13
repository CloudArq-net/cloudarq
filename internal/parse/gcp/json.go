package gcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// value is one JSON value of a document together with the bytes it was
// written in. An object keeps its members in document order with every
// duplicate: a member written twice is a fact about the document, which of
// the two Google applies is not stated, and a map would answer the
// question silently by keeping one. The AWS and Azure parsers carry
// readers with the same job; this is the third, sized to this document,
// and the three are the cases the shared reader that follows this unit is
// designed from.
type value struct {
	kind    kind
	text    string   // kindString: the decoded text
	truth   bool     // kindBool
	items   []*value // kindList
	members []member // kindObject, in document order, duplicates kept
	raw     []byte   // the value's own bytes, sliced from the document
}

type member struct {
	name  string
	value *value
}

// kind is the JSON type, which decides what a member can be read as and
// names the type in the sentence about a member that has the wrong one.
type kind int

const (
	kindNull kind = iota
	kindBool
	kindNumber
	kindString
	kindList
	kindObject
)

func (k kind) String() string {
	return [...]string{"null", "a boolean", "a number", "a string", "a list", "an object"}[k]
}

// nestingLimit bounds how deep containers may nest. The reader descends
// once per open container, so without a bound of its own a document
// nested deep enough would overflow the goroutine stack, a fatal error no
// recover catches; whether the decoder stops it first depends on the
// toolchain, which under go1.27.1 refuses a list nested past 10,000
// levels and under Go 1.24 refused nothing, as the AWS parser's reader
// recorded. The bound sits below both, so the refusal is this package's
// sentence everywhere. A provider document nests six deep at most, a list
// page, the provider, x509, its trust store, the anchor list, an anchor,
// so it refuses nothing Google produces, and the members this parser
// skips, a trust store or SAML metadata, are read under it like every
// other.
const nestingLimit = 1000

// readDocument decodes exactly one JSON value from raw. Anything else is
// an error: empty input, invalid UTF-8, a \u escape naming half of a
// UTF-16 pair, containers nested past nestingLimit, a second value or
// other bytes after the first. Invalid UTF-8 and a lone surrogate are
// refused rather than decoded, because the decoder would replace each
// with U+FFFD and an Exact built from that value would not be the
// customer's value.
func readDocument(raw []byte) (*value, error) {
	for at := 0; at < len(raw); {
		r, size := utf8.DecodeRune(raw[at:])
		if r == utf8.RuneError && size == 1 {
			return nil, fmt.Errorf("not valid UTF-8 at byte %d", at)
		}
		at += size
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, errors.New("empty input")
	}
	r := &reader{dec: json.NewDecoder(bytes.NewReader(raw)), raw: raw}
	// Numbers are never interpreted, so a literal too large for a float
	// is not a reason to refuse the document.
	r.dec.UseNumber()
	root, err := r.value()
	if err != nil {
		return nil, err
	}
	if _, err := r.dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("a second value")
		}
		return nil, fmt.Errorf("after the document: %w", err)
	}
	return root, nil
}

// reader builds values from the decoder's token stream and recovers the
// bytes each token was written in. The decoder reports only where a
// token ends; where it begins is the first byte after the previous token
// that is not whitespace or a separator, which in a well-formed stream is
// the token's own first byte.
type reader struct {
	dec   *json.Decoder
	raw   []byte
	depth int // containers open around the token being read
}

// token reads the next token and its byte range. The end of the input is
// always premature here: a value or a member was expected, and the
// decoder reports a bare EOF inside an open container, which read as the
// end of the document would accept a truncated provider.
func (r *reader) token() (tok json.Token, start, end int, err error) {
	start = int(r.dec.InputOffset())
	tok, err = r.dec.Token()
	switch {
	case errors.Is(err, io.EOF):
		return nil, 0, 0, io.ErrUnexpectedEOF
	case err != nil:
		return nil, 0, 0, err
	}
	end = int(r.dec.InputOffset())
	for start < end && betweenTokens(r.raw[start]) {
		start++
	}
	return tok, start, end, nil
}

// betweenTokens reports whether a byte can sit between two tokens of a
// well-formed stream: whitespace, or the separator of a member or an item.
func betweenTokens(b byte) bool {
	switch b {
	case ' ', '\t', '\r', '\n', ':', ',':
		return true
	}
	return false
}

func (r *reader) value() (*value, error) {
	tok, start, end, err := r.token()
	if err != nil {
		return nil, err
	}
	return r.build(tok, start, end)
}

// build is the value a token begins: the scalar itself, or the container
// an opening delimiter starts. The decoder validates the nesting, so a
// closing delimiter never arrives where a value begins.
func (r *reader) build(tok json.Token, start, end int) (*value, error) {
	raw := r.raw[start:end]
	switch t := tok.(type) {
	case json.Delim:
		return r.container(t == '{', start)
	case string:
		if at, lone := loneSurrogate(raw); lone {
			return nil, fmt.Errorf("lone surrogate escape at byte %d", start+at)
		}
		return &value{kind: kindString, text: t, raw: raw}, nil
	case bool:
		return &value{kind: kindBool, truth: t, raw: raw}, nil
	case json.Number:
		return &value{kind: kindNumber, raw: raw}, nil
	}
	return &value{kind: kindNull, raw: raw}, nil
}

// container reads the members of an object or the items of a list up to
// the closing delimiter, which arrives through the same call as the next
// member, so that a document cut off anywhere inside fails through one
// path. An error ends the whole parse, so the depth is restored only on
// the way back from a container that was read.
func (r *reader) container(object bool, start int) (*value, error) {
	if r.depth == nestingLimit {
		return nil, fmt.Errorf("nested more than %d levels deep at byte %d", nestingLimit, start)
	}
	r.depth++
	v, closing := &value{kind: kindList}, json.Delim(']')
	if object {
		v.kind, closing = kindObject, json.Delim('}')
	}
	for {
		tok, tokStart, end, err := r.token()
		if err != nil {
			return nil, err
		}
		if tok == closing {
			v.raw = r.raw[start:end]
			r.depth--
			return v, nil
		}
		if !object {
			item, err := r.build(tok, tokStart, end)
			if err != nil {
				return nil, err
			}
			v.items = append(v.items, item)
			continue
		}
		// Between the braces the decoder yields member names, which are
		// always strings, before each value.
		if at, lone := loneSurrogate(r.raw[tokStart:end]); lone {
			return nil, fmt.Errorf("lone surrogate escape at byte %d", tokStart+at)
		}
		val, err := r.value()
		if err != nil {
			return nil, err
		}
		v.members = append(v.members, member{name: tok.(string), value: val})
	}
}

// loneSurrogate finds, in the bytes of one string token, a \u escape that
// names a UTF-16 surrogate without its partner: a high one not followed by
// a low one, or a low one on its own. The decoder has validated the token,
// so every backslash begins an escape and every \u carries four hex
// digits; only the pairing is left unchecked.
func loneSurrogate(token []byte) (int, bool) {
	for i := 0; i+6 <= len(token); i++ {
		if token[i] != '\\' {
			continue
		}
		if token[i+1] != 'u' {
			i++
			continue
		}
		unit := codeUnit(token[i+2 : i+6])
		switch {
		case unit < 0xD800 || unit > 0xDFFF:
			i += 5
		case unit <= 0xDBFF && lowSurrogateFollows(token[i+6:]):
			i += 11
		default:
			return i, true
		}
	}
	return 0, false
}

func lowSurrogateFollows(rest []byte) bool {
	if len(rest) < 6 || rest[0] != '\\' || rest[1] != 'u' {
		return false
	}
	unit := codeUnit(rest[2:6])
	return 0xDC00 <= unit && unit <= 0xDFFF
}

// codeUnit reads the four hex digits of a \u escape. The decoder has
// refused anything but hex digits in those positions, so every byte is
// one, in either case.
func codeUnit(hex []byte) uint16 {
	var n uint16
	for _, b := range hex {
		switch {
		case b <= '9':
			n = n<<4 | uint16(b-'0')
		case b <= 'F':
			n = n<<4 | uint16(b-'A'+10)
		default:
			n = n<<4 | uint16(b-'a'+10)
		}
	}
	return n
}
