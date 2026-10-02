package aws

import (
	"bytes"
	"encoding/json"
	"io"
	"time"
)

// Format names the bundle's shape. A reader refuses any other, so a bundle
// from a newer collector is never read as if it were this one.
const Format = "cloudarq.collect/v1"

// Bundle is what one collection of one AWS account wrote: who the account
// is, the roles exactly as ListRoles paged them, and everything AWS refused
// or the collector capped. A refusal or a cap is a line here, never a gap a
// reader could take for an account with nothing in it.
type Bundle struct {
	Format      string    `json:"format"`
	Provider    string    `json:"provider"`
	Account     string    `json:"account"`
	Partition   string    `json:"partition"`
	Alias       *string   `json:"alias"`
	CollectedAt time.Time `json:"collected_at"`
	Collector   string    `json:"collector"`
	Pages       []Page    `json:"pages"`
	Refused     []Refused `json:"refused"`
	Limits      []string  `json:"limits"`
}

// Page is one ListRoles answer, its fields named as IAM names them.
type Page struct {
	Roles       []Role  `json:"Roles"`
	IsTruncated bool    `json:"IsTruncated"`
	Marker      *string `json:"Marker,omitempty"`
}

// Role is one role as ListRoles returned it. The trust policy is the JSON
// text the account holds: IAM sends it percent-encoded, and it is decoded
// once, which loses nothing, so a reader hashes and parses what the
// customer wrote.
type Role struct {
	Path                     string    `json:"Path"`
	RoleName                 string    `json:"RoleName"`
	RoleId                   string    `json:"RoleId"`
	Arn                      string    `json:"Arn"`
	CreateDate               time.Time `json:"CreateDate"`
	AssumeRolePolicyDocument *string   `json:"AssumeRolePolicyDocument,omitempty"`
	Description              *string   `json:"Description,omitempty"`
	MaxSessionDuration       *int32    `json:"MaxSessionDuration,omitempty"`
}

// Refused is one call AWS answered with an error, in AWS's own code and words.
type Refused struct {
	Call    string `json:"call"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Partial reports whether anything was refused or capped.
func (b Bundle) Partial() bool {
	return len(b.Refused) > 0 || len(b.Limits) > 0
}

// Roles counts the roles across every page.
func (b Bundle) Roles() int {
	n := 0
	for _, page := range b.Pages {
		n += len(page.Roles)
	}
	return n
}

// Encode writes the bundle as indented JSON with a final newline. Field
// order is the structs', so the same answers give the same bytes, and
// nothing is HTML-escaped: a policy's "<" or "&" is written as the account
// holds it.
func (b Bundle) Encode(w io.Writer) error {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(b); err != nil {
		return err
	}
	_, err := w.Write(out.Bytes())
	return err
}
