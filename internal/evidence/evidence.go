// Package evidence defines the provenance record that every finding carries.
//
// The rule this package exists to enforce: if a claim cannot produce the API
// response that proves it, the claim is a bug, not a finding.
package evidence

import (
	"crypto/sha256"
	"encoding/json"
	"time"
)

// Status is a first-class outcome, not an error channel.
//
// StatusDenied in particular is a FACT, not an absence. A scanner that reports
// "no external principals" because a call was refused is worse than one that
// reports nothing at all.
type Status string

const (
	StatusOK            Status = "ok"
	StatusDenied        Status = "denied"
	StatusThrottled     Status = "throttled"
	StatusUnsupported   Status = "unsupported"
	StatusNotConfigured Status = "not_configured"
)

// Conclusive reports whether this record can support a finding. Anything else
// must surface as Unknown in the evaluator, never as a clean result.
func (s Status) Conclusive() bool { return s == StatusOK || s == StatusNotConfigured }

// Record is one API call and its verbatim response.
//
// Bytes is never re-marshalled. Round-tripping through a decoder destroys
// evidence -- notably duplicate condition keys, which the Terraform AWS
// provider collapses before AWS ever sees the policy. The customer's source of
// truth and the deployed bytes can disagree, and only the bytes settle it.
type Record struct {
	API       string          `json:"api"`
	Params    string          `json:"params"` // canonical JSON, sorted keys
	Status    Status          `json:"status"`
	Bytes     json.RawMessage `json:"bytes,omitempty"`
	SHA256    string          `json:"sha256"`
	FetchedAt time.Time       `json:"fetched_at"` // deliberately NOT part of any hash
}

// New builds a Record and seals its digest.
func New(api, params string, status Status, body []byte, at time.Time) Record {
	sum := sha256.Sum256(body)
	return Record{
		API:       api,
		Params:    params,
		Status:    status,
		Bytes:     json.RawMessage(body),
		SHA256:    hex(sum[:]),
		FetchedAt: at,
	}
}

const hexdigits = "0123456789abcdef"

func hex(b []byte) string {
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}
