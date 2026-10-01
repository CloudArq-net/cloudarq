package ring

import (
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/CloudArq-net/cloudarq/internal/parse/aws"
	"github.com/CloudArq-net/cloudarq/internal/trust"
)

// The bounds on a declaration, which arrives as --owner values or from any
// other caller of the engine, and the engine bounds everything it reads.
const (
	MaxDeclarationBytes     = 16 << 10
	MaxDeclarationLines     = 64
	MaxDeclarationLineBytes = 512
)

// Declaration is one owner a user declared as theirs. Nothing in the
// engine infers ownership: an owner nobody declared stays a named outsider.
type Declaration struct {
	Namespace Namespace
	// Scope is ScopeOwner for github, ScopeAccount or ScopeOrganisation for
	// aws, ScopeProvider for saml and ScopeTenant for issuer.
	Scope Scope
	// Name and ID are a GitHub owner's, either or both.
	Name string
	ID   string
	// Value is an AWS account or organisation id, a SAML provider's ARN, or
	// a per-tenant issuer's normalised URL.
	Value string
}

// Declarations is a declaration as read: the owners, normalised, sorted by
// their text and deduplicated so that one set has one form, and every line
// refused, with its reason, in the order written. Past a bound it is the
// bound it went past and nothing else: the whole input is refused, as a
// document past its bound is.
type Declarations struct {
	Owners  []Declaration
	Refused []Refusal
	Overrun *Overrun
}

// Overrun is how a declaration went past a bound, as values: internal/report
// words it, since every sentence the answer carries is composed there.
type Overrun struct {
	Bound Bound
	// Line is the line past MaxDeclarationLineBytes, 1-based, and zero for
	// the other bounds.
	Line int
	// Size is what the bound counts, as given: the declaration's bytes or
	// lines, or the line's bytes.
	Size int
}

// Bound is one of the bounds a declaration is read within.
type Bound int

const (
	// DeclarationBytes is MaxDeclarationBytes, over the whole declaration.
	DeclarationBytes Bound = iota
	// DeclarationLines is MaxDeclarationLines.
	DeclarationLines
	// LineBytes is MaxDeclarationLineBytes, over one line.
	LineBytes
)

// Refusal is one line that declares nothing, and why, echoed as written so
// that the user sees what was not read.
type Refusal struct {
	Line   int // 1-based
	Text   string
	Reason Reason
}

// Reason is why a line declares nothing. Its words are internal/report's,
// which composes every sentence the answer carries. The zero value,
// NoReason, is a line that declares an owner.
type Reason int

const (
	// NoReason: the line declares an owner.
	NoReason Reason = iota
	// NotUTF8: the line is not UTF-8.
	NotUTF8
	// NoNamespace: the line names no namespace before a colon.
	NoNamespace
	// UnknownNamespace: the namespace is none owners are declared in.
	UnknownNamespace
	// ClaimsNotRead: an owner on GitLab, HCP Terraform or Buildkite, whose
	// claims the engine does not read.
	ClaimsNotRead
	// NoOwner: github: with nothing after it.
	NoOwner
	// ARepository: a GitHub repository, which the declaration grammar has
	// no form for.
	ARepository
	// NotAGitHubOwner: not a name, a name@id or an @id.
	NotAGitHubOwner
	// NotAnAWSID: neither an account id nor an organisation id.
	NotAnAWSID
	// NotASAMLProvider: not the ARN of a SAML provider.
	NotASAMLProvider
	// NotAnIssuerURL: not an https issuer URL a trust policy's provider can
	// name.
	NotAnIssuerURL
)

var reasonNames = [...]string{"none", "not-utf-8", "no-namespace", "unknown-namespace", "claims-not-read", "no-owner", "a-repository", "not-a-github-owner", "not-an-aws-id", "not-a-saml-provider", "not-an-issuer-url"}

// String is the reason's id in the answer's vocabulary.
func (r Reason) String() string { return name(reasonNames[:], int(r), "reason") }

// String is the declaration's normalised text, one form per owner: what
// the answer echoes and what --owner takes.
func (d Declaration) String() string {
	if d.Namespace != NamespaceGitHub {
		return string(d.Namespace) + ":" + d.Value
	}
	if d.ID == "" {
		return "github:" + d.Name
	}
	return "github:" + d.Name + "@" + d.ID
}

// ReadDeclarations reads one declaration per line, UTF-8. Past a bound the
// whole input is refused, as a document past its bound is; a line the
// syntax does not allow is refused alone, with its reason; a blank line
// declares nothing and is not refused.
func ReadDeclarations(text string) Declarations {
	if len(text) > MaxDeclarationBytes {
		return Declarations{Overrun: &Overrun{Bound: DeclarationBytes, Size: len(text)}}
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) > MaxDeclarationLines {
		return Declarations{Overrun: &Overrun{Bound: DeclarationLines, Size: len(lines)}}
	}
	var out Declarations
	byText := map[string]Declaration{}
	for i, raw := range lines {
		raw = strings.TrimSuffix(raw, "\r")
		if len(raw) > MaxDeclarationLineBytes {
			return Declarations{Overrun: &Overrun{Bound: LineBytes, Line: i + 1, Size: len(raw)}}
		}
		line := trimBlanks(raw)
		if line == "" {
			continue
		}
		d, reason := declaration(line)
		if reason != NoReason {
			out.Refused = append(out.Refused, Refusal{Line: i + 1, Text: raw, Reason: reason})
			continue
		}
		byText[d.String()] = d
	}
	// The text is the owner's one form, so keying by it drops repeats, and
	// sorting the texts orders the owners with the sort of strings the
	// engine already links, where a sort of Declaration would add its own.
	texts := make([]string, 0, len(byText))
	for text := range byText {
		texts = append(texts, text)
	}
	slices.Sort(texts)
	for _, text := range texts {
		out.Owners = append(out.Owners, byText[text])
	}
	return out
}

// trimBlanks drops the spaces and tabs around a line, and nothing else.
func trimBlanks(s string) string {
	for s != "" && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for s != "" && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

// declaration reads one line, or says why it declares nothing. The
// namespace is ASCII case-folded, being the syntax's own word; the owner
// keeps its case, because names compare exactly.
func declaration(line string) (Declaration, Reason) {
	if !utf8.ValidString(line) {
		return Declaration{}, NotUTF8
	}
	namespace, value, found := strings.Cut(line, ":")
	if !found {
		return Declaration{}, NoNamespace
	}
	switch Namespace(lowerASCII(namespace)) {
	case NamespaceGitHub:
		return githubDeclaration(value)
	case NamespaceAWS:
		return awsDeclaration(value)
	case NamespaceSAML:
		if !aws.IsSAMLIssuer(trust.IssuerRef(value)) {
			return Declaration{}, NotASAMLProvider
		}
		return Declaration{Namespace: NamespaceSAML, Scope: ScopeProvider, Value: value}, NoReason
	case NamespaceIssuer:
		return issuerDeclaration(value)
	}
	switch lowerASCII(namespace) {
	case "gitlab", "terraform", "buildkite":
		return Declaration{}, ClaimsNotRead
	}
	return Declaration{}, UnknownNamespace
}

// githubDeclaration reads a GitHub owner in GitHub's own notation: a name,
// a name and its id joined by @, or an id alone after @. The grammar has no
// form for a repository.
func githubDeclaration(value string) (Declaration, Reason) {
	if value == "" {
		return Declaration{}, NoOwner
	}
	if strings.Contains(value, "/") {
		return Declaration{}, ARepository
	}
	name, id, withID := strings.Cut(value, "@")
	nameOK := isName(name) || withID && name == ""
	idOK := !withID || isNumber(id)
	if !nameOK || !idOK {
		return Declaration{}, NotAGitHubOwner
	}
	return Declaration{Namespace: NamespaceGitHub, Scope: ScopeOwner, Name: name, ID: id}, NoReason
}

// isName reports whether s can be written as an owner's name here: some
// printable ASCII, none of it a space or a delimiter of a subject. Whether
// GitHub allows it is the census's to say; a name no owner can have only
// ever fails to match a pin. A character beyond ASCII is refused: no
// census's owner characters reach beyond it, and which such characters are
// printable is the Unicode version of the toolchain that built the engine,
// so reading it would accept a name on one build and refuse it on another.
func isName(s string) bool {
	return s != "" && !strings.ContainsFunc(s, func(r rune) bool {
		return r <= ' ' || r > '~' || strings.ContainsRune(":@/", r)
	})
}

func isNumber(s string) bool {
	return s != "" && !strings.ContainsFunc(s, func(r rune) bool { return r < '0' || r > '9' })
}

// awsDeclaration reads an AWS account or organisation by its id, in the
// form the parser reads one in a policy.
func awsDeclaration(value string) (Declaration, Reason) {
	for _, claim := range aws.TenancyClaims() {
		t, ok := aws.TenantOfValue(claim, value)
		if scope, known := awsScope(t); ok && known && t.ID == value {
			return Declaration{Namespace: NamespaceAWS, Scope: scope, Value: value}, NoReason
		}
	}
	return Declaration{}, NotAnAWSID
}

// issuerDeclaration reads a per-tenant issuer's tenant by its issuer URL,
// through the parser's own reading of a provider identifier, so that the
// address a link writes and the issuer a policy names compare alike: a URL
// the parser would not file a principal under, one with a wildcard or a
// host spelled to fold onto another, declares nothing. The whole URL is
// the tenant, never the census entry and the tenant it names: an EKS
// cluster's id is the same in every region, and no sentence makes it
// unique across them.
func issuerDeclaration(value string) (Declaration, Reason) {
	if len(value) < len("https://") || lowerASCII(value[:len("https://")]) != "https://" || strings.ContainsFunc(value, unicode.IsSpace) {
		return Declaration{}, NotAnIssuerURL
	}
	issuer, ok := aws.ProviderIssuer(value)
	if !ok {
		return Declaration{}, NotAnIssuerURL
	}
	return Declaration{Namespace: NamespaceIssuer, Scope: ScopeTenant, Value: string(issuer)}, NoReason
}

// Names reports whether the declaration names o as the user's, by the
// case rule of the issuer o was pinned under, which f holds. It is the rule
// the classifier declares owners by, and the one a reader asking which
// declarations moved nothing must ask.
func (d Declaration) Names(o Owner, f Facts) bool {
	return d.covers(o, f.Tenancy != nil && f.Tenancy.NamesIgnoreCase)
}

// SpelledLike reports whether d is the declaration of o written in another
// letter case: what a user wrote who took names to compare without case,
// which they do not unless the census says so.
func (d Declaration) SpelledLike(o Owner) bool {
	written, pinned := d.String(), o.Declaration()
	return pinned != "" && pinned != written && lowerASCII(pinned) == lowerASCII(written)
}

// covers reports whether the declaration names o: the same namespace, scope
// and kind. A GitHub name matches a name pin, compared exactly unless the
// census records that names are unique regardless of case; a GitHub id
// matches an id pin; a per-tenant issuer's URL matches its tenant's issuer;
// an AWS id and a SAML provider's ARN match themselves.
func (d Declaration) covers(o Owner, ignoreCase bool) bool {
	switch {
	case o.Namespace == "" || d.Namespace != o.Namespace || d.Scope != o.Scope:
		return false
	case d.Namespace == NamespaceGitHub && o.Kind == KindName:
		return d.Name != "" && (d.Name == o.Value || ignoreCase && equalFoldASCII(d.Name, o.Value))
	case d.Namespace == NamespaceGitHub:
		return d.ID != "" && d.ID == o.Value
	case d.Namespace == NamespaceIssuer:
		issuer, _ := trust.NormaliseIssuer(string(o.Issuer))
		return d.Value == string(issuer)
	}
	return d.Value == o.Value
}

// equalFoldASCII compares two names folding ASCII letters and nothing else:
// the case rule the census can verify is about the characters an owner's
// name may hold, and folding a Kelvin sign onto a k would match an owner no
// declaration named.
func equalFoldASCII(a, b string) bool { return lowerASCII(a) == lowerASCII(b) }

// lowerASCII lower-cases ASCII letters and nothing else, for the words of
// the declaration syntax and the names the case rule compares.
func lowerASCII(s string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, s)
}
