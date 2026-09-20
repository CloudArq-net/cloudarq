package report

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// token is a pasted token's claims, in the order the token lists them, and
// as the engine compares them: a string claim is its text, any other value
// is its JSON as written, compacted.
type token struct {
	order   []string
	values  map[trust.ClaimKey]string
	decoded bool // read from the middle segment of a whole token
}

// readToken accepts the decoded payload, a JSON object, or the whole
// token, whose middle segment is decoded first. Only the payload is read:
// a signature is not checked here.
func readToken(text []byte) (token, error) {
	if len(text) > MaxTokenBytes {
		return token{}, fmt.Errorf("the token is %d bytes; the engine reads up to %d", len(text), MaxTokenBytes)
	}
	trimmed := bytes.TrimSpace(text)
	tok := token{values: map[trust.ClaimKey]string{}}
	if payload, ok := jwtPayload(trimmed); ok {
		trimmed, tok.decoded = payload, true
	}
	if err := nesting(trimmed, MaxTokenNesting, "token"); err != nil {
		return token{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	open, err := dec.Token()
	if err != nil || open != json.Delim('{') {
		return token{}, errors.New("the token is neither a decoded payload, a JSON object, nor a whole token with a payload segment")
	}
	for dec.More() {
		name, err := dec.Token()
		if err != nil {
			return token{}, fmt.Errorf("read the token's claims: %w", err)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return token{}, fmt.Errorf("read the token's claims: %w", err)
		}
		claim := name.(string)
		if _, seen := tok.values[trust.ClaimKey(claim)]; !seen {
			tok.order = append(tok.order, claim)
		}
		tok.values[trust.ClaimKey(claim)] = claimText(raw)
	}
	if _, err := dec.Token(); err != nil {
		return token{}, fmt.Errorf("read the token's claims: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return token{}, errors.New("the token has bytes after its payload")
	}
	return tok, nil
}

// jwtPayload is the decoded middle segment of a three-segment token, when
// the text has that shape and the segment is base64url.
func jwtPayload(text []byte) ([]byte, bool) {
	parts := strings.Split(string(text), ".")
	if len(parts) != 3 || strings.ContainsAny(string(text), " \t\r\n{}") {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, false
	}
	return payload, true
}

// claimText is a claim's value as the engine compares it: a string is its
// own text; a number, a boolean, null, a list or an object is its JSON,
// compacted, because AWS compares the string form of the request value.
func claimText(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return string(raw)
	}
	return compact.String()
}
