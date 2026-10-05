package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/CloudArq-net/cloudarq/internal/ring"
)

// A collector's bundle in, findings out: every role of one AWS account
// answered with the owners the reader declared, in the shape a scan's
// findings are kept in. Each answer is the one AdmitsFor renders for the
// role's trust policy, with one owner more placed as the reader's: the
// account the bundle was read from, recognised, which the answer keeps
// apart from what was declared. Beside it, a role AWS made for one of its
// services says so (managed.go), which reads the trust of a role on AWS's
// path and nothing else, and never touches the answer; and the owners the
// bundle's AWS Organization names, which only the reader can say are
// theirs, are asked about, with what a yes would move.

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
// are, the AWS Organization that account is in, the roles, and what the
// collector could not read.
type Bundle struct {
	Account      string
	Partition    string
	Alias        *string
	Organization Organization
	CollectedAt  *string
	Collector    *string
	Roles        []BundleRole
	Refused      []BundleRefusal
	Limits       []string
	digest       [sha256.Size]byte
}

// BundleRole is one role: its ARN, its name, its path, its trust policy's
// text, and, when AWS made it for one of its services, what it is. Path is
// nil when the bundle lists the role with no path: cloudarq-collect has
// written every role's path since its first release, and a bundle written
// without one was read before the engine read paths, under the same
// format, so it is read still, the path not known.
type BundleRole struct {
	Arn      string
	Name     string
	Path     *string
	Document []byte
	Managed  *Managed
}

// Organization is what a bundle says of the AWS Organization its account is
// in: the organization's ID, the account that manages it and its feature
// set, for a member. A bundle written before cloudarq-collect read
// Organizations carries nothing about it, which is not read, never an
// account in none.
type Organization struct {
	// Status is what the bundle says. Values: member, not-a-member,
	// refused, not-read.
	Status            string
	ID                string
	ManagementAccount string
	FeatureSet        string
}

// The statuses of an Organization, as the bundle and the findings write them.
const (
	orgMember  = "member"
	orgNone    = "not-a-member"
	orgRefused = "refused"
	orgNotRead = "not-read"
)

// describeCall is the call a bundle lists as refused when the collector
// could not read the Organization.
const describeCall = "organizations:DescribeOrganization"

// BundleRefusal is one call the cloud refused while the bundle was
// collected, in the cloud's own code and words, but for the people an ARN
// in them names, each read as (removed).
type BundleRefusal struct {
	Call, Code, Message string
}

// collected is the bundle's JSON, the members this reads and no other.
type collected struct {
	Format       *string `json:"format"`
	Provider     string  `json:"provider"`
	Account      string  `json:"account"`
	Partition    string  `json:"partition"`
	Alias        *string `json:"alias"`
	Organization *struct {
		Status               string `json:"status"`
		ID                   string `json:"id"`
		Arn                  string `json:"arn"`
		ManagementAccount    string `json:"management_account"`
		ManagementAccountArn string `json:"management_account_arn"`
		FeatureSet           string `json:"feature_set"`
	} `json:"organization"`
	CollectedAt *string `json:"collected_at"`
	Collector   *string `json:"collector"`
	Pages       []struct {
		Roles []struct {
			Path                     *string `json:"Path"`
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
			if role.Path != nil {
				if err := listedPath(*role.Path, role.Arn, prefix); err != nil {
					return Bundle{}, err
				}
			}
			var document []byte
			if role.AssumeRolePolicyDocument != nil {
				document = []byte(*role.AssumeRolePolicyDocument)
			}
			b.Roles = append(b.Roles, BundleRole{Arn: role.Arn, Name: role.RoleName, Path: role.Path, Document: document, Managed: managedBy(role.Path, document)})
		}
	}
	if len(b.Roles) > MaxBundleRoles {
		return Bundle{}, fmt.Errorf("this bundle holds %d roles, more than the %d IAM holds in one account", len(b.Roles), MaxBundleRoles)
	}
	// A refusal's message is the one text of the bundle read through the
	// strip: a bundle written before the collector took the person out of
	// what AWS refused still names them, and the engine reads every bundle.
	// The digest above is of the file as given, names and all.
	for _, r := range c.Refused {
		b.Refused = append(b.Refused, BundleRefusal{Call: r.Call, Code: r.Code, Message: withoutPeople(r.Message)})
	}
	b.Limits = append(b.Limits, c.Limits...)
	org, err := c.organization(b.Refused)
	if err != nil {
		return Bundle{}, err
	}
	b.Organization = org
	return b, nil
}

// organization reads what the bundle says of its account's Organization
// and holds it together: a member's ID as AWS writes one, its management
// account an account ID, and both ARNs the ones AWS writes for that
// organization and that account in the bundle's partition; a status that
// names no organization naming none; and a refusal that says so listed
// where the bundle lists what was refused. The management account and the
// organization are owners the findings ask the reader about, so one that
// does not hold together refuses the whole bundle, as a stranger's role
// does. Whatever else the member carries, an email address among it, is
// not read.
func (c collected) organization(refused []BundleRefusal) (Organization, error) {
	o := c.Organization
	if o == nil {
		return Organization{Status: orgNotRead}, nil
	}
	const org = "this bundle's organization "
	listed := slices.ContainsFunc(refused, func(r BundleRefusal) bool { return r.Call == describeCall })
	names := o.ID != "" || o.Arn != "" || o.ManagementAccount != "" || o.ManagementAccountArn != "" || o.FeatureSet != ""
	switch {
	case o.Status != orgMember && o.Status != orgNone && o.Status != orgRefused:
		return Organization{}, fmt.Errorf(org+"says %+q, which is none of member, not-a-member and refused, so this bundle is not as cloudarq-collect wrote it", o.Status)
	case o.Status == orgRefused && !listed:
		return Organization{}, fmt.Errorf(org+"says refused, and the bundle lists no refusal of %s, so this bundle is not as cloudarq-collect wrote it", describeCall)
	case o.Status != orgRefused && listed:
		return Organization{}, fmt.Errorf(org+"says %s, and the bundle lists %s as refused, so this bundle is not as cloudarq-collect wrote it", o.Status, describeCall)
	case o.Status != orgMember && names:
		return Organization{}, fmt.Errorf(org+"says %s and names an organization, so this bundle is not as cloudarq-collect wrote it", o.Status)
	case o.Status != orgMember:
		return Organization{Status: o.Status}, nil
	case !organizationID(o.ID):
		return Organization{}, fmt.Errorf(org+"ID %+q is not one AWS writes, o- followed by 10 to 32 lower-case letters or digits", o.ID)
	case !awsAccount(o.ManagementAccount):
		return Organization{}, fmt.Errorf(org+"names the management account %+q, which is not an AWS account ID, twelve digits", o.ManagementAccount)
	}
	arn := "arn:" + c.Partition + ":organizations::" + o.ManagementAccount + ":"
	switch {
	case o.Arn != arn+"organization/"+o.ID:
		return Organization{}, fmt.Errorf(org+"ARN %+q is not the ARN of %s, managed by %s in %s, which AWS writes %+q", o.Arn, o.ID, o.ManagementAccount, c.Partition, arn+"organization/"+o.ID)
	case o.ManagementAccountArn != arn+"account/"+o.ID+"/"+o.ManagementAccount:
		return Organization{}, fmt.Errorf(org+"management account's ARN %+q is not the ARN of %s in %s, which AWS writes %+q", o.ManagementAccountArn, o.ManagementAccount, o.ID, arn+"account/"+o.ID+"/"+o.ManagementAccount)
	case !featureSet(o.FeatureSet):
		return Organization{}, fmt.Errorf(org+"feature set %+q is not one AWS writes, a word of capitals and underscores such as ALL", o.FeatureSet)
	}
	return Organization{Status: orgMember, ID: o.ID, ManagementAccount: o.ManagementAccount, FeatureSet: o.FeatureSet}, nil
}

// organizationID is the pattern AWS gives an organization's ID,
// ^o-[a-z0-9]{10,32}$.
func organizationID(s string) bool {
	if len(s) < 12 || len(s) > 34 || s[:2] != "o-" {
		return false
	}
	return !strings.ContainsFunc(s[2:], func(r rune) bool { return (r < 'a' || r > 'z') && (r < '0' || r > '9') })
}

// featureSet is a feature set as AWS writes one, ALL or
// CONSOLIDATED_BILLING today: a word of capitals and underscores. A set AWS
// adds later reads, since nothing is decided by it; any other text does not.
func featureSet(s string) bool {
	return s != "" && len(s) <= 64 && !strings.ContainsFunc(s, func(r rune) bool { return (r < 'A' || r > 'Z') && r != '_' })
}

// maxPathLength is the longest path CreateRole accepts, in characters,
// which for a path of printable ASCII are its bytes.
const maxPathLength = 512

// listedPath checks the path a role is listed at against the two things
// that fix it: CreateRole's own pattern, "/" alone or printable ASCII
// between a leading and a trailing "/", and the role's ARN, which IAM
// writes as the path without its leading "/", then the name. The path is
// what tells a role AWS made for one of its services from one anybody
// made, so a path IAM would not write, or one its own ARN contradicts,
// refuses the whole bundle, as a stranger's role does.
func listedPath(path, arn, prefix string) error {
	if !iamPath(path) {
		return fmt.Errorf(`the role %+q is listed with the path %+q, which IAM does not write: a path is "/" alone, or printable ASCII between a leading and a trailing "/"`, arn, path)
	}
	if len(path) > maxPathLength {
		return fmt.Errorf("the role %+q is listed with a path of %d characters, longer than the %d IAM allows", arn, len(path), maxPathLength)
	}
	resource := strings.TrimPrefix(arn, prefix)
	named := "/" + resource[:strings.LastIndexByte(resource, '/')+1]
	if path != named {
		return fmt.Errorf("the role %+q is listed with the path %+q, and its ARN names the path %+q, so this bundle is not as cloudarq-collect wrote it", arn, path, named)
	}
	return nil
}

// iamPath is CreateRole's pattern for a path,
// (/)|(/[!-~]+/).
func iamPath(path string) bool {
	if path == "/" {
		return true
	}
	if len(path) < 3 || path[0] != '/' || path[len(path)-1] != '/' {
		return false
	}
	for i := 1; i < len(path)-1; i++ {
		if path[i] < '!' || path[i] > '~' {
			return false
		}
	}
	return true
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
// and the account the bundle was read from recognised; the bundle's AWS
// Organization, the owners it names that the findings ask about, and for
// each role what a yes would move; and engine, this engine's name and
// version, recorded beside them. A bundle this does not read renders as the
// format and the reason alone.
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
	recognised := b.recognised()
	e.str("provider", "aws")
	e.str("account", b.Account)
	e.optional("alias", b.Alias)
	e.organization(b.Organization)
	e.key("recognised")
	e.recognitions(recognitionsOf(recognised))
	asked := b.Suggested(owners)
	e.suggested(asked)
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
		e.optional("path", role.Path)
		e.managed(role.Managed)
		digest := sha256.Sum256(role.Document)
		e.str("document_sha256", hex.EncodeToString(digest[:]))
		e.key("answer")
		answer, placing := answerPlaced(role.Document, owners, recognised)
		e.answer(answer)
		e.moves(placing.moves(asked))
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

// organization writes what the bundle says of its account's Organization:
// the status, and for a member its ID, management account and feature set.
func (e *encoder) organization(o Organization) {
	e.key("organization")
	saved := e.begin()
	e.str("status", o.Status)
	e.strOmit("id", o.ID)
	e.strOmit("management_account", o.ManagementAccount)
	e.strOmit("feature_set", o.FeatureSet)
	e.end(saved)
}

// AnswerFor is the answer the findings give one of the bundle's roles,
// with the owners declared one a line: its trust policy's, with the
// account the bundle was read from recognised as the reader's.
func (b Bundle) AnswerFor(role BundleRole, owners []byte) Answer {
	return admitsRecognising(role.Document, owners, b.recognised())
}

// recognised are the owners the findings recognise as the reader's
// without a declaration: the account the scan read, which the collector
// read with the reader's own credentials, and nothing else. The management
// account of its Organization and the Organization itself are not: a
// reseller or a managed service provider may run the one, and the other
// may hold other companies' accounts, so either, counted as the reader's
// unasked, would hide exactly the outsider the findings exist to show. The
// findings ask about those instead.
func (b Bundle) recognised() []ring.Declaration {
	return ring.ReadDeclarations("aws:" + b.Account).Owners
}

// Suggestion is an owner the findings ask the reader about, because the
// bundle names it and only the reader can say whether it is theirs: the
// declaration that answers yes, the question in words, and whether the
// owners declared answer it already.
type Suggestion struct {
	Declaration string
	Question    string
	Declared    bool
	owner       ring.Declaration
}

// Suggested are the owners the findings ask the reader about, with the
// owners declared one a line: for an account in an AWS Organization, the
// account that manages it, unless that is the account the scan read, which
// is recognised, and the Organization. Neither is the reader's until they
// declare it.
func (b Bundle) Suggested(owners []byte) []Suggestion {
	out := []Suggestion{}
	o := b.Organization
	if o.Status != orgMember {
		return out
	}
	declared := ring.ReadDeclarations(string(owners)).Owners
	ask := func(owner ring.Declaration, question string) {
		out = append(out, Suggestion{Declaration: owner.String(), Question: question, Declared: slices.Contains(declared, owner), owner: owner})
	}
	if o.ManagementAccount != b.Account {
		ask(ring.Declaration{Namespace: ring.NamespaceAWS, Scope: ring.ScopeAccount, Value: o.ManagementAccount}, managementQuestionWords)
	}
	ask(ring.Declaration{Namespace: ring.NamespaceAWS, Scope: ring.ScopeOrganisation, Value: o.ID}, organizationQuestionWords)
	return out
}

// Move is what one owner the findings ask about would change of a role,
// were the reader to declare it: the question, and the headline the role's
// answer would then open on.
type Move struct {
	Declaration string
	Question    string
	Sentence    string
	Spans       []Span
}

// Finding is what the findings say of one of the bundle's roles, with the
// owners declared one a line, from one reading of its trust policy: the
// answer AnswerFor gives, and one Move for each owner the findings ask
// about and the reader has not declared whose declaring would move where a
// population of the role's grants lands.
func (b Bundle) Finding(role BundleRole, owners []byte) (Answer, []Move) {
	answer, placing := answerPlaced(role.Document, owners, b.recognised())
	return answer, placing.moves(b.Suggested(owners))
}

// placing is a policy's grants as an answer placed them: the policy as
// read, the owners declared and those recognised, and where each grant
// landed.
type placing struct {
	read       reading
	declared   ring.Declarations
	recognised []ring.Declaration
	placed     []placed
}

// moves places the grants again with each owner asked about and not
// declared added to the owners declared; where a population lands
// elsewhere, the role says what its answer would then open on. A policy
// the engine did not read, or owners past their bounds, placed nothing and
// have nothing to move.
//
// Only an owner a population is pinned to can move one: the classifier
// asks of the owners declared nothing but whether one names an owner it
// pinned a population to (classifier.covered, in internal/ring). So the
// grants are placed again for such an owner alone, and a role pinned to
// neither owner asked about costs the questions nothing.
func (p *placing) moves(asked []Suggestion) []Move {
	out := []Move{}
	if p == nil {
		return out
	}
	for _, s := range asked {
		if s.Declared || !p.pinnedTo(s.owner) {
			continue
		}
		yes := ring.Declarations{Owners: append(slices.Clone(p.declared.Owners), s.owner)}
		placed := p.read.place(yes.Owners, p.recognised...)
		if !landsElsewhere(p.placed, placed) {
			continue
		}
		var a Answer
		a.rings(placed, yes)
		spans := stripped(wouldReadWords(s.Declaration, a.Headline.Spans))
		out = append(out, Move{Declaration: s.Declaration, Question: s.Question, Sentence: plain(spans), Spans: spans})
	}
	return out
}

// pinnedTo reports whether owner names an owner a population of the
// grants is pinned to, by the rule the classifier names one by.
func (p *placing) pinnedTo(owner ring.Declaration) bool {
	for _, g := range p.placed {
		for _, pop := range g.placement.Populations {
			if slices.ContainsFunc(pop.Owners, func(o ring.Owner) bool { return owner.Names(o, g.facts) }) {
				return true
			}
		}
	}
	return false
}

// landsElsewhere reports whether a population of the same grants, placed
// twice, lands in one place the first time and another the second.
func landsElsewhere(before, after []placed) bool {
	for i := range before {
		for j, pop := range before[i].placement.Populations {
			if pop.Place != after[i].placement.Populations[j].Place {
				return true
			}
		}
	}
	return false
}

// suggested writes the owners the findings ask about.
func (e *encoder) suggested(asked []Suggestion) {
	e.key("suggested")
	e.b = append(e.b, '[')
	for i, s := range asked {
		e.comma(i)
		saved := e.begin()
		e.str("declaration", s.Declaration)
		e.str("question", s.Question)
		e.boolean("declared", s.Declared)
		e.end(saved)
	}
	e.b = append(e.b, ']')
}

// moves writes what each owner asked about would change of a role.
func (e *encoder) moves(moves []Move) {
	e.key("would_move")
	e.b = append(e.b, '[')
	for i, m := range moves {
		e.comma(i)
		saved := e.begin()
		e.str("declaration", m.Declaration)
		e.str("question", m.Question)
		e.str("sentence", m.Sentence)
		e.spans("spans", m.Spans)
		e.end(saved)
	}
	e.b = append(e.b, ']')
}

// recognitionsOf is the owners recognised, as the findings write them.
func recognitionsOf(recognised []ring.Declaration) []Recognition {
	out := []Recognition{}
	for _, d := range recognised {
		out = append(out, Recognition{Declaration: d.String(), Sentence: recognisedWords})
	}
	return out
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
