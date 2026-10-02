// Package aws reads one AWS account for the engine: who the account is, its
// roles with their trust policies, and its alias, kept as AWS answered them.
//
// It only reads. Every call is named on the explain writer before it is
// made, so a person can see what was asked of their account before it is
// asked, and every call AWS refuses is written into the bundle with AWS's
// own code and words. Nothing is evaluated here: the engine reads the
// bundle, offline.
package aws

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// PageSize is the most roles ListRoles returns in one answer.
const PageSize = 1000

// MaxPages bounds the paging. IAM holds at most 5,000 roles in an account,
// five pages at PageSize, so a marker still asking for more after this many
// pages is not ending, and the collector stops and says so.
const MaxPages = 100

// Reader holds what a collection needs: the two clients, the clock it
// stamps the bundle with, where to name each call (nil names nothing) and
// the collector's own name and version.
type Reader struct {
	STS       *sts.Client
	IAM       *iam.Client
	Clock     func() time.Time
	Explain   io.Writer
	Collector string
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
	r.roles(ctx, &bundle)
	return bundle, nil
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

// refusal keeps AWS's own code and message. An error that never reached
// AWS - the network, a cancelled run - has no code of AWS's, and is named
// as unanswered with its own words.
func refusal(call string, err error) Refused {
	var api smithy.APIError
	if errors.As(err, &api) {
		return Refused{Call: call, Code: api.ErrorCode(), Message: api.ErrorMessage()}
	}
	return Refused{Call: call, Code: "Unanswered", Message: err.Error()}
}
