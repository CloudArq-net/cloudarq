package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// A collector's bundle in, findings out: every role of one AWS account
// answered with the owners the reader declared, in the shape a scan's
// findings are kept in. Each answer is the one AdmitsFor renders for the role's
// trust policy alone, byte for byte; nothing here reads a policy.

// BundleFormat is the one bundle this reads, as cloudarq-collect writes it;
// FindingsFormat is what it writes.
const (
	BundleFormat   = "cloudarq.collect/v1"
	FindingsFormat = "cloudarq.findings/v1"
)

// MaxBundleBytes bounds the bundle read. IAM holds at most 5,000 roles in an
// account, each trust policy at most 4,096 characters, which written out
// with each role's other fields comes to about 30 MB; a file past this
// bound is not one account's roles.
const MaxBundleBytes = 64 << 20

// MaxBundleRoles is IAM's ceiling on the roles in one account.
const MaxBundleRoles = 5000

// Bundle is a collector's bundle as the engine reads it: whose roles they
// are, the roles, and what the collector could not read.
type Bundle struct {
	Account     string
	Partition   string
	Alias       *string
	CollectedAt *string
	Collector   *string
	Roles       []BundleRole
	Refused     []BundleRefusal
	Limits      []string
	digest      [sha256.Size]byte
}

// BundleRole is one role: its ARN, its name and its trust policy's text.
type BundleRole struct {
	Arn      string
	Name     string
	Document []byte
}

// BundleRefusal is one call the cloud refused while the bundle was
// collected, in the cloud's own code and words.
type BundleRefusal struct {
	Call, Code, Message string
}

// collected is the bundle's JSON, the members this reads and no other.
type collected struct {
	Format      *string `json:"format"`
	Provider    string  `json:"provider"`
	Account     string  `json:"account"`
	Partition   string  `json:"partition"`
	Alias       *string `json:"alias"`
	CollectedAt *string `json:"collected_at"`
	Collector   *string `json:"collector"`
	Pages       []struct {
		Roles []struct {
			RoleName                 string  `json:"RoleName"`
			Arn                      string  `json:"Arn"`
			AssumeRolePolicyDocument *string `json:"AssumeRolePolicyDocument"`
		} `json:"Roles"`
	} `json:"pages"`
	Refused []struct {
		Call    string `json:"call"`
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"refused"`
	Limits []string `json:"limits"`
}

// ReadBundle reads a bundle, refusing in words a person can act on
// anything that is not one AWS account's bundle in the format this reads.
func ReadBundle(raw []byte) (Bundle, error) {
	if len(raw) > MaxBundleBytes {
		return Bundle{}, fmt.Errorf("this file is larger than %d MB, more than one AWS account's roles make, so it is not a bundle cloudarq-collect wrote", MaxBundleBytes>>20)
	}
	var c collected
	if err := json.Unmarshal(raw, &c); err != nil {
		return Bundle{}, fmt.Errorf("this file is not a CloudArq bundle (%v); give the engine the file cloudarq-collect aws writes", err)
	}
	switch {
	case c.Format == nil:
		return Bundle{}, fmt.Errorf("this file is not a CloudArq bundle: it names no format; give the engine the file cloudarq-collect aws writes")
	case *c.Format != BundleFormat:
		return Bundle{}, fmt.Errorf("this bundle's format is %+q, and this engine reads %s; if a newer cloudarq-collect wrote it, read it with a newer engine", *c.Format, BundleFormat)
	case c.Provider != "aws":
		return Bundle{}, fmt.Errorf("this bundle is of %+q, and this engine reads bundles of AWS accounts", c.Provider)
	case !awsAccount(c.Account):
		return Bundle{}, fmt.Errorf("this bundle's account %+q is not an AWS account ID, which is twelve digits", c.Account)
	case c.Partition == "" || strings.ContainsAny(c.Partition, ":/"):
		return Bundle{}, fmt.Errorf("this bundle's partition %+q is not an AWS partition such as aws", c.Partition)
	}
	b := Bundle{
		Account: c.Account, Partition: c.Partition, Alias: c.Alias, CollectedAt: c.CollectedAt, Collector: c.Collector,
		Roles: []BundleRole{}, Refused: []BundleRefusal{}, Limits: []string{}, digest: sha256.Sum256(raw),
	}
	prefix := "arn:" + c.Partition + ":iam::" + c.Account + ":role/"
	seen := map[string]bool{}
	for _, page := range c.Pages {
		for _, role := range page.Roles {
			if !strings.HasPrefix(role.Arn, prefix) {
				return Bundle{}, fmt.Errorf("the role %+q is not a role of account %s, so this bundle is not one account's", role.Arn, c.Account)
			}
			if seen[role.Arn] {
				return Bundle{}, fmt.Errorf("the role %+q appears twice in this bundle", role.Arn)
			}
			seen[role.Arn] = true
			var document []byte
			if role.AssumeRolePolicyDocument != nil {
				document = []byte(*role.AssumeRolePolicyDocument)
			}
			b.Roles = append(b.Roles, BundleRole{Arn: role.Arn, Name: role.RoleName, Document: document})
		}
	}
	if len(b.Roles) > MaxBundleRoles {
		return Bundle{}, fmt.Errorf("this bundle holds %d roles, more than the %d IAM holds in one account", len(b.Roles), MaxBundleRoles)
	}
	for _, r := range c.Refused {
		b.Refused = append(b.Refused, BundleRefusal{Call: r.Call, Code: r.Code, Message: r.Message})
	}
	b.Limits = append(b.Limits, c.Limits...)
	return b, nil
}

func awsAccount(s string) bool {
	if len(s) != 12 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// Findings reads a bundle and renders its findings as JSON: every role
// answered with the owners declared, one a line as AdmitsFor takes them,
// and engine, this engine's name and version, recorded beside them. A
// bundle this does not read renders as the format and the reason alone.
func Findings(bundle, owners []byte, engine string) []byte {
	return AppendFindings(nil, bundle, owners, engine)
}

// AppendFindings appends to dst what Findings renders and returns the
// extended buffer, as AppendAdmits does for one policy.
func AppendFindings(dst, bundle, owners []byte, engine string) []byte {
	e := &encoder{b: dst}
	saved := e.begin()
	e.str("format", FindingsFormat)
	b, err := ReadBundle(bundle)
	if err != nil {
		e.str("error", err.Error())
		e.end(saved)
		return e.b
	}
	e.str("provider", "aws")
	e.str("account", b.Account)
	e.optional("alias", b.Alias)
	e.optional("collected_at", b.CollectedAt)
	e.optional("collector", b.Collector)
	e.str("engine", engine)
	e.str("bundle_sha256", hex.EncodeToString(b.digest[:]))
	e.key("roles")
	e.b = append(e.b, '[')
	for i, role := range b.Roles {
		e.comma(i)
		inner := e.begin()
		e.str("arn", role.Arn)
		e.str("name", role.Name)
		digest := sha256.Sum256(role.Document)
		e.str("document_sha256", hex.EncodeToString(digest[:]))
		e.key("answer")
		e.b = admitsWith(e.b, role.Document, owners)
		e.end(inner)
	}
	e.b = append(e.b, ']')
	e.key("refused")
	e.b = append(e.b, '[')
	for i, r := range b.Refused {
		e.comma(i)
		inner := e.begin()
		e.str("call", r.Call)
		e.str("code", r.Code)
		e.str("message", r.Message)
		e.end(inner)
	}
	e.b = append(e.b, ']')
	e.key("limits")
	e.b = append(e.b, '[')
	for i, limit := range b.Limits {
		e.comma(i)
		e.quote(limit)
	}
	e.b = append(e.b, ']')
	e.end(saved)
	return e.b
}

// optional writes a member whose value may be absent as null.
func (e *encoder) optional(name string, v *string) {
	e.key(name)
	if v == nil {
		e.null()
		return
	}
	e.quote(*v)
}
