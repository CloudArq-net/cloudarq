package azure

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// value is one JSON value as the decoder yielded it. Members keep document
// order with duplicates intact: a member written twice is a fact about the
// document that a map would erase, and which of the two Entra applies
// cannot be known from the bytes. The AWS parser has a reader with the
// same job and a different API; this one was written against it rather
// than imported, by the decision that a shared reader is a refactor for
// when the third parser arrives, and the two are to be reconciled into one
// package then, once, rather than a third time.
type value struct {
	kind    kind
	text    string   // a string's decoded text, or a number's literal
	members []member // kindObject, in document order, duplicates kept
	items   []*value // kindList
	// raw is the value's own bytes: no surrounding whitespace or
	// separators, escapes as written, sliced from the caller's buffer. A
	// Credential keeps a copy of its own, and a Grant quotes that copy back,
	// never a re-rendering.
	raw json.RawMessage
}

type member struct {
	name  string
	value *value
}

// kind is the JSON type, for the total readers in credential.go and for
// the sentence an anomaly prints when a member has the wrong one.
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

// readDocument decodes exactly one JSON value from raw. Anything else is an
// error: empty input, invalid UTF-8, a byte order mark, containers nested
// past nestingLimit, a second value or other bytes after the first. The
// stream decoder would stop at the first value's closing brace, so the end
// of the input is checked deliberately; a second credential concatenated
// after the first must not vanish. Invalid UTF-8 is refused rather than
// decoded, because the decoder would replace each bad byte with U+FFFD and
// an Exact built from that value would not be the customer's value; a \u
// escape naming half of a UTF-16 pair is refused for the same reason, by
// the reader, since the bytes themselves are valid.
func readDocument(raw []byte) (*value, error) {
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

// loneSurrogate finds, in the bytes of one string token as written, a \u
// escape that names a UTF-16 surrogate without its partner: a high one not
// followed by a low one, or a low one on its own. The decoder has already
// validated the token, so every backslash begins an escape and every \u
// has its four hex digits; the closing quote keeps an escape from being the
// last five bytes, which is why the loop can stop that early.
func loneSurrogate(token []byte) (int, bool) {
	for i := 0; i+5 < len(token); i++ {
		if token[i] != '\\' {
			continue
		}
		if token[i+1] != 'u' {
			i++
			continue
		}
		first := codeUnit(token[i+2 : i+6])
		switch {
		case first < 0xD800 || first > 0xDFFF:
			i += 5
		case first > 0xDBFF || !isLowSurrogateEscape(token[i+6:]):
			return i, true
		default:
			i += 11
		}
	}
	return 0, false
}

func isLowSurrogateEscape(rest []byte) bool {
	if len(rest) < 6 || rest[0] != '\\' || rest[1] != 'u' {
		return false
	}
	second := codeUnit(rest[2:6])
	return 0xDC00 <= second && second <= 0xDFFF
}

// codeUnit reads the four hex digits of a \u escape. The decoder has
// already refused an escape with anything else in those positions, so
// there is no error to return.
func codeUnit(hex []byte) uint16 {
	var n uint16
	for _, b := range hex {
		n = n<<4 | uint16(hexDigit(b))
	}
	return n
}

func hexDigit(b byte) byte {
	switch {
	case b <= '9':
		return b - '0'
	case b <= 'F':
		return b - 'A' + 10
	}
	return b - 'a' + 10
}

// nestingLimit bounds how deep containers may nest. The reader descends
// once per container, so a document nested far enough exhausts the
// goroutine stack, which is fatal and beyond any recover: a 2,000,000-deep
// list killed the process under Go 1.24, whose decoder applies no limit of
// its own. A credential document nests four deep, collection, list,
// credential, expression, so the bound refuses nothing Graph produces; it
// sits below the 10,000 the newer decoder allows so that the refusal is
// this package's sentence on every toolchain, and far below the depth at
// which the stack gives out.
const nestingLimit = 1000

// reader walks the token stream and recovers each token's byte range. The
// decoder reports only where a token ends; where it begins is the first
// byte after the previous token that is not whitespace, ':' or ','. In a
// well-formed stream nothing else can sit between two tokens, and no token
// starts with one of those bytes, so the scan lands exactly on the token.
type reader struct {
	dec   *json.Decoder
	raw   []byte
	depth int // containers open at this point of the walk
}

// next returns the token a value or a member needs, so the end of the input
// here is always premature: the decoder reports a bare EOF inside an open
// object, and a caller reading that as "end of document" would accept a
// truncated credential.
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
	return tok, start, end, nil
}

func isBetweenTokens(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == ':' || b == ','
}

// readValue reads the next token and the value it begins.
func (r *reader) readValue() (*value, error) {
	tok, start, end, err := r.next()
	if err != nil {
		return nil, err
	}
	return r.value(tok, start, end)
}

// value builds the value a token begins: the token itself for a scalar, or
// the object or list it opens. The decoder validates nesting, so a
// delimiter here opens a container; a closing one cannot arrive where a
// value begins.
func (r *reader) value(tok json.Token, start, end int) (*value, error) {
	switch t := tok.(type) {
	case json.Delim:
		return r.container(t, start)
	case string:
		if at, lone := loneSurrogate(r.raw[start:end]); lone {
			return nil, fmt.Errorf("lone surrogate escape at byte %d", start+at)
		}
		return &value{kind: kindString, text: t, raw: r.raw[start:end]}, nil
	case json.Number:
		return &value{kind: kindNumber, text: t.String(), raw: r.raw[start:end]}, nil
	case bool:
		return &value{kind: kindBool, raw: r.raw[start:end]}, nil
	}
	return &value{kind: kindNull, raw: r.raw[start:end]}, nil
}

// container reads the object or list an opening delimiter begins, one
// level deeper than the walk is now, or refuses it at the nesting limit.
// An error ends the whole parse, so the depth need only be restored on the
// way back from a container that was read.
func (r *reader) container(open json.Delim, start int) (*value, error) {
	if r.depth == nestingLimit {
		return nil, fmt.Errorf("nested more than %d levels deep at byte %d", nestingLimit, start)
	}
	r.depth++
	var v *value
	var err error
	if open == '{' {
		v, err = r.readObject(start)
	} else {
		v, err = r.readList(start)
	}
	r.depth--
	return v, err
}

// readObject and readList read members or items until the closing
// delimiter, which arrives through the same call as the next member, so
// that a document cut off anywhere inside the container fails through one
// path. Asking the decoder whether more follows would open a second path
// that depends on where the decoder reports the truncation, which differs
// between the toolchain's two JSON implementations.
func (r *reader) readObject(start int) (*value, error) {
	v := &value{kind: kindObject}
	for {
		tok, nameStart, end, err := r.next()
		if err != nil {
			return nil, err
		}
		if tok == json.Delim('}') {
			v.raw = r.raw[start:end]
			return v, nil
		}
		if at, lone := loneSurrogate(r.raw[nameStart:end]); lone {
			return nil, fmt.Errorf("lone surrogate escape at byte %d", nameStart+at)
		}
		val, err := r.readValue()
		if err != nil {
			return nil, err
		}
		// Between the braces the decoder yields member names, which are
		// always strings, and the closing brace.
		v.members = append(v.members, member{name: tok.(string), value: val})
	}
}

func (r *reader) readList(start int) (*value, error) {
	v := &value{kind: kindList}
	for {
		tok, itemStart, end, err := r.next()
		if err != nil {
			return nil, err
		}
		if tok == json.Delim(']') {
			v.raw = r.raw[start:end]
			return v, nil
		}
		item, err := r.value(tok, itemStart, end)
		if err != nil {
			return nil, err
		}
		v.items = append(v.items, item)
	}
}
