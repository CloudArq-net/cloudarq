package report

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/eval"
	"github.com/CloudArq-net/cloudarq/internal/registry"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// token is a pasted token's claims, in the order the token lists them: a
// string claim is its text, any other value its JSON as written, compacted,
// which is what the table shows.
type token struct {
	order  []string
	values map[trust.ClaimKey]string
	// null holds the claims whose value is JSON null, which the engine
	// compares as the empty string, as decoding null into a string leaves
	// it.
	null map[trust.ClaimKey]bool
	// shapes holds what a claim is when it is neither a string nor null: a
	// list, an object, a number or a boolean. AWS documents a string
	// condition as comparing a key to a string, and no rule for what one
	// compares in such a claim, so the engine compares none.
	shapes  map[trust.ClaimKey]string
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
	tok := token{values: map[trust.ClaimKey]string{}, null: map[trust.ClaimKey]bool{}, shapes: map[trust.ClaimKey]string{}}
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
		tok.null[trust.ClaimKey(claim)] = string(bytes.TrimSpace(raw)) == "null"
		tok.shapes[trust.ClaimKey(claim)] = shapeOf(raw)
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

// claimText is a claim's value as the table shows it: a string is its own
// text, and a number, a boolean, null, a list or an object is its JSON,
// compacted.
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

// shapeOf names what a claim's value is when it is neither a string nor
// null, and is empty for those two. The decoder has read the value, so its
// first byte says which it is.
func shapeOf(raw json.RawMessage) string {
	switch bytes.TrimSpace(raw)[0] {
	case '"', 'n':
		return ""
	case '[':
		return "a list"
	case '{':
		return "an object"
	case 't', 'f':
		return "a boolean"
	}
	return "a number"
}

// keyRead is what AWS reads from a token for one condition key a grant holds:
// the claim it reads, and the value there, which the token may not carry.
type keyRead struct {
	claim   string
	value   string
	present bool
	null    bool // the token sets the claim to JSON null
	// shape is what the claim is when it is neither a string nor null, as
	// token.shapes holds it, and what AWS compares there is not known.
	shape string
	// unnamed is set when what AWS's table names as what it reads, held in
	// claim, is no claim a token is known to carry: a phrase, as Login with
	// Amazon's "User ID", or a spelling no vendor sentence ties to a claim
	// of that name. What the token carries for the key is then not known.
	unnamed bool
	// instead is the reading AWS takes instead when the token sets no value
	// for claim. It is held beside a claim set to the empty string or to
	// null, both of which the engine compares as the empty string, since
	// AWS does not say whether either is a value.
	instead *keyRead
}

// readKey is what AWS reads for key from a token of issuer's. The census
// records the claim AWS reads each key it documents from, which is not
// always the claim of the key's name: oaud reads aud, and aud reads azp, or
// aud when the token sets no azp. A key the census does not record for the
// issuer is one the parser kept unread or as written, and reads the claim of
// its own name.
func (tok token) readKey(issuer trust.IssuerRef, key trust.ClaimKey) keyRead {
	read, documented := registry.AWSConditionKeyClaim(issuer, string(key))
	switch {
	case !documented:
		return tok.claim(string(key))
	case read.Claim == "":
		return keyRead{claim: read.Table, unnamed: true}
	}
	r := tok.namedClaim(read.Claim)
	if read.Fallback == "" || r.unnamed {
		return r
	}
	instead := tok.namedClaim(read.Fallback)
	switch {
	case !r.present:
		return instead
	case r.value == "":
		r.instead = &instead
	}
	return r
}

// namedClaim is the token's value for a claim as AWS's table writes its
// name, which may be a phrase no token's payload holds.
func (tok token) namedClaim(claim string) keyRead {
	if _, named := trust.Claim(claim); !named {
		return keyRead{claim: claim, unnamed: true}
	}
	return tok.claim(claim)
}

// claim is the token's value for one claim.
func (tok token) claim(claim string) keyRead {
	value, present := tok.values[trust.ClaimKey(claim)]
	return keyRead{claim: claim, value: value, present: present, null: tok.null[trust.ClaimKey(claim)], shape: tok.shapes[trust.ClaimKey(claim)]}
}

// claims are the claims the reading reads: its own, and the one AWS reads
// instead when the token leaves which it reads open.
func (r keyRead) claims() []string {
	if r.instead == nil {
		return []string{r.claim}
	}
	return []string{r.claim, r.instead.claim}
}

// verdict is whether a reading meets a constraint: it does, it does not,
// or the token leaves the reading open and its readings disagree.
type verdict int

const (
	misses verdict = iota
	meets
	open
)

// against is the reading's verdict on a constraint. An absent claim meets
// only a constraint that admits everything, as the engine's Admits holds.
// What AWS compares in a claim no token is known to carry, or in one that is
// not a string, is not known, and the verdict is open.
func (r keyRead) against(s eval.StringSet) verdict {
	if r.unnamed || r.shape != "" {
		return open
	}
	v := misses
	if r.present && s.Contains(r.value) || !r.present && s.IsTop() {
		v = meets
	}
	if r.instead != nil && r.instead.against(s) != v {
		return open
	}
	return v
}
