// Package aws reads one AWS account for the engine: who the account is, its
// roles with their trust policies, its alias, and the AWS Organization it is
// in, kept as AWS answered them.
//
// It only reads. Every call is named on the explain writer before it is
// made, so a person can see what was asked of their account before it is
// asked, and every call AWS refuses is written into the bundle with AWS's
// own code and words, but for the person who made the call, whose name
// becomes (removed). Nothing is evaluated here: the engine reads the
// bundle, offline.
package aws

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/processcreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// PageSize is the most roles ListRoles returns in one answer.
const PageSize = 1000

// MaxPages bounds the paging. IAM holds at most 5,000 roles in an account,
// five pages at PageSize, so a marker still asking for more after this many
// pages is not ending, and the collector stops and says so.
const MaxPages = 100

// Reader holds what a collection needs: the three clients, the clock it
// stamps the bundle with, where to name each call (nil names nothing), the
// collector's own name and version, and the home directory of whoever runs
// it, which the SDK's words for a call that was never answered can name
// (empty replaces nothing).
type Reader struct {
	STS           *sts.Client
	IAM           *iam.Client
	Organizations *organizations.Client
	Clock         func() time.Time
	Explain       io.Writer
	Collector     string
	Home          string
}

// Collect reads the account the credentials belong to. Without that
// account, which STS answers with no permission at all, there is nothing to
// write and the error says why; everything after it that AWS refuses is a
// line in the bundle instead.
func (r Reader) Collect(ctx context.Context) (Bundle, error) {
	r.explain("sts:GetCallerIdentity", "which account these credentials belong to")
	caller, err := r.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return Bundle{}, fmt.Errorf("could not learn which account these credentials belong to: %w", err)
	}
	account, arn := sdk.ToString(caller.Account), sdk.ToString(caller.Arn)
	partition, ok := partitionOf(arn)
	if account == "" || !ok {
		return Bundle{}, fmt.Errorf("STS answered without an account and an ARN to read the partition from (account %+q, ARN %+q)", account, arn)
	}
	bundle := Bundle{
		Format:      Format,
		Provider:    "aws",
		Account:     account,
		Partition:   partition,
		CollectedAt: r.Clock().UTC(),
		Collector:   r.Collector,
		Pages:       []Page{},
		Refused:     []Refused{},
		Limits:      []string{},
	}
	r.alias(ctx, &bundle)
	r.organization(ctx, &bundle)
	r.roles(ctx, &bundle)
	for i := range bundle.Refused {
		bundle.Refused[i].Message = r.withoutTheCaller(bundle.Refused[i], sdk.ToString(caller.UserId))
	}
	return bundle, nil
}

// withoutTheCaller is what the bundle says of a refusal: its message
// without whoever ran the collector, or anyone else an ARN in it names.
// The passes run in this order:
//
//  1. The caller's exact principal ID, when it holds a colon with something
//     after it, loses what follows the colon wherever it starts outside an
//     ARN: an assumed role's AROA…:session and a federated user's
//     account:name hold no "arn:", so the grammar never sees them. An IAM
//     user's ID and the root user's, the account itself, hold no colon and
//     name no one. Inside an ARN the grammar alone decides: a federated
//     user's name can begin a resource type, as "fe" begins
//     federated-user/, and the principal taken out of an ARN would leave
//     one the grammar no longer reads, naming whoever it names. Outside,
//     no boundary is read around the principal: removing too much is the
//     safer error.
//  2. The grammar, over every ARN in the message, the caller's own among
//     them: the grammar reads an ARN wherever it stands, whatever words
//     surround it, so the caller's ARN needs no pass of its own.
//  3. For a call that was never answered, whose words are the SDK's and
//     can name a file under the home directory, the home becomes "~". It
//     runs after the grammar, so a home inside a person's ARN goes with
//     the ARN rather than leaving the rest of its name behind. AWS's own
//     refusals are AWS's words, and only the grammar reads them.
//  4. The grammar again, so the collector's last act is the grammar's and
//     the engine's own strip, reading the bundle, changes nothing written
//     here: a home holding a colon, once replaced, can change how many
//     fields an ARN has.
func (r Reader) withoutTheCaller(refused Refused, principal string) string {
	message := withoutThePrincipal(refused.Message, principal)
	message = withoutPeople(message)
	if refused.Code == unanswered {
		message = withoutHome(message, r.Home)
	}
	return withoutPeople(message)
}

// withoutThePrincipal is message with what follows principal's colon taken
// out wherever principal starts outside an ARN; a principal without a
// colon, or with nothing after it, takes nothing out. An ARN is what the
// grammar reads as one, a stretch nextARNs gives, and a principal starting
// in one is the grammar's to read. One that starts outside and runs on
// into an ARN, as account:barn runs into an "arn:", takes the rest of that
// stretch with it: the ARN cut at its "arn:" would be one the grammar no
// longer reads.
func withoutThePrincipal(message, principal string) string {
	colon := strings.IndexByte(principal, ':')
	if colon < 0 || colon == len(principal)-1 {
		return message
	}
	var out strings.Builder
	copied := 0 // message[:copied] is in out
	arn, arnEnd := nextARNs(message, 0)
	for from := 0; ; {
		found := strings.Index(message[from:], principal)
		if found < 0 {
			break
		}
		at, end := from+found, from+found+len(principal)
		for arnEnd <= at {
			arn, arnEnd = nextARNs(message, arnEnd)
		}
		if arn <= at { // in an ARN, and so is everything to the stretch's end
			from = arnEnd
			continue
		}
		for arnEnd < end {
			arn, arnEnd = nextARNs(message, arnEnd)
		}
		if arn < end { // it runs on into an ARN
			end = arnEnd
		}
		out.WriteString(message[copied : at+colon+1])
		out.WriteString(removed)
		copied, from = end, end
	}
	if out.Len() == 0 {
		return message
	}
	out.WriteString(message[copied:])
	return out.String()
}

// withoutHome is message with home written "~" wherever it stands, in the
// form the SDK joins paths in, filepath.Clean's, and as given when that
// differs, the clean form first, so that a home given with a trailing
// separator leaves the separator after the "~". Nothing is replaced for an
// empty home, a relative one, or the file system's root, whose every
// separator would become "~". No boundary is read: /srv/jo inside /srv/joe
// becomes ~e, which removes too much and keeps nothing.
func withoutHome(message, home string) string {
	if home == "" {
		return message
	}
	clean := filepath.Clean(home)
	if !filepath.IsAbs(clean) || filepath.Dir(clean) == clean {
		return message
	}
	message = strings.ReplaceAll(message, clean, "~")
	if home != clean {
		message = strings.ReplaceAll(message, home, "~")
	}
	return message
}

func (r Reader) alias(ctx context.Context, bundle *Bundle) {
	r.explain("iam:ListAccountAliases", "the account's alias, its default name")
	answer, err := r.IAM.ListAccountAliases(ctx, &iam.ListAccountAliasesInput{})
	if err != nil {
		bundle.Refused = append(bundle.Refused, refusal("iam:ListAccountAliases", err))
		return
	}
	// An account has at most one alias.
	if len(answer.AccountAliases) > 0 {
		bundle.Alias = sdk.String(answer.AccountAliases[0])
	}
}

// organization asks which AWS Organization the account is in, which any
// account in one may ask. Organizations answers from one endpoint in each
// partition, which the client picks from the partition of the region it was
// given. Only the fields the bundle names are kept: the answer's email
// address and policy types never reach the bundle.
func (r Reader) organization(ctx context.Context, bundle *Bundle) {
	const call = "organizations:DescribeOrganization"
	r.explain(call, "the AWS Organization the account is in, and which account manages it")
	answer, err := r.Organizations.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	var notInUse *types.AWSOrganizationsNotInUseException
	switch {
	case errors.As(err, &notInUse):
		bundle.Organization = Organization{Status: "not-a-member"}
	case err != nil:
		bundle.Organization = Organization{Status: "refused"}
		bundle.Refused = append(bundle.Refused, refusal(call, err))
	case answer.Organization == nil:
		bundle.Organization = Organization{Status: "refused"}
		bundle.Refused = append(bundle.Refused, Refused{Call: call, Code: unanswered, Message: "AWS answered without an organization"})
	default:
		o := answer.Organization
		bundle.Organization = Organization{
			Status:               "member",
			ID:                   sdk.ToString(o.Id),
			Arn:                  sdk.ToString(o.Arn),
			ManagementAccount:    sdk.ToString(o.MasterAccountId),
			ManagementAccountArn: sdk.ToString(o.MasterAccountArn),
			FeatureSet:           string(o.FeatureSet),
		}
	}
}

func (r Reader) roles(ctx context.Context, bundle *Bundle) {
	var marker *string
	for page := 1; ; page++ {
		if page > MaxPages {
			bundle.Limits = append(bundle.Limits, fmt.Sprintf(
				"iam:ListRoles was still truncated after %d pages; IAM holds at most 5,000 roles in an account, so the collector stopped there", MaxPages))
			return
		}
		r.explain("iam:ListRoles", fmt.Sprintf("page %d of the roles and their trust policies", page))
		answer, err := r.IAM.ListRoles(ctx, &iam.ListRolesInput{Marker: marker, MaxItems: sdk.Int32(PageSize)})
		if err != nil {
			bundle.Refused = append(bundle.Refused, refusal("iam:ListRoles", err))
			return
		}
		kept := Page{Roles: make([]Role, 0, len(answer.Roles)), IsTruncated: answer.IsTruncated, Marker: answer.Marker}
		for _, role := range answer.Roles {
			document, decoded := trustPolicy(role.AssumeRolePolicyDocument)
			if !decoded {
				bundle.Limits = append(bundle.Limits, fmt.Sprintf(
					"the trust policy of %s was not percent-encoded as IAM sends it, so it is kept as it arrived", sdk.ToString(role.Arn)))
			}
			kept.Roles = append(kept.Roles, Role{
				Path:                     sdk.ToString(role.Path),
				RoleName:                 sdk.ToString(role.RoleName),
				RoleId:                   sdk.ToString(role.RoleId),
				Arn:                      sdk.ToString(role.Arn),
				CreateDate:               sdk.ToTime(role.CreateDate).UTC(),
				AssumeRolePolicyDocument: document,
				Description:              role.Description,
				MaxSessionDuration:       role.MaxSessionDuration,
			})
		}
		bundle.Pages = append(bundle.Pages, kept)
		if !answer.IsTruncated {
			return
		}
		marker = answer.Marker
	}
}

func (r Reader) explain(call, reads string) {
	if r.Explain != nil {
		fmt.Fprintf(r.Explain, "cloudarq-collect: calling %s: %s\n", call, reads)
	}
}

// trustPolicy decodes IAM's percent-encoding once. Path unescaping, not
// query unescaping: a "+" in a policy is a plus sign, and IAM encodes the
// ones it sends. A document that does not decode is kept as it came, and
// the second result says so.
func trustPolicy(raw *string) (*string, bool) {
	if raw == nil {
		return nil, true
	}
	text, err := url.PathUnescape(*raw)
	if err != nil {
		return raw, false
	}
	return &text, true
}

// partitionOf reads the partition from an ARN, "arn:<partition>:...".
func partitionOf(arn string) (string, bool) {
	parts := strings.SplitN(arn, ":", 3)
	if len(parts) < 3 || parts[0] != "arn" || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

// unanswered is the code of a call that never reached AWS, or that AWS
// answered without what was asked: its words are the SDK's or the
// collector's, not AWS's.
const unanswered = "Unanswered"

// credentialProcessFailed is what the bundle says of a call whose
// credentials a profile's credential_process could not give.
const credentialProcessFailed = "the credentials could not be refreshed: the credential process failed or wrote what the SDK could not read; its output is not kept"

// refusal keeps AWS's own code and message, which Collect then takes the
// caller out of. An error that never reached AWS - the network, a cancelled
// run - has no code of AWS's, and is named as unanswered with its own words,
// but for a credential process's failure: when the SDK cannot read what the
// process wrote, its words hold all of it, the new secret access key and
// session token and whatever else the process printed, so the collector
// says it in a sentence of its own instead.
func refusal(call string, err error) Refused {
	var api smithy.APIError
	if errors.As(err, &api) {
		return Refused{Call: call, Code: api.ErrorCode(), Message: api.ErrorMessage()}
	}
	var process *processcreds.ProviderError
	if errors.As(err, &process) {
		return Refused{Call: call, Code: unanswered, Message: credentialProcessFailed}
	}
	return Refused{Call: call, Code: unanswered, Message: err.Error()}
}
