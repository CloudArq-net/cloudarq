package report

import (
	"bytes"
	"encoding/json"
	"maps"
	"slices"
	"testing"
)

// The parts of what a finding says, as members of the finding: who the
// way in lets in, each by a kind and a value; what it comes through; the
// condition its term holds, as the finding's id is made from it; and the
// conditions its statement writes that the term does not read. These tests
// read them through the JSON the entry points write, as a consumer does.

// partsPolicy holds one way in for each rule an AWS principal or a GitHub
// token meets, and a service beside them, which meets none: an outside
// account asked for no external ID under two conditions the engine does
// not read, one of them written with a value twice; three accounts named
// by a condition, of which the reader declares one; anyone with an AWS
// account; and anyone with a GitHub account.
var partsPolicy = trustOf(
	statement("", `{"AWS":"arn:aws:iam::444455556666:root"}`, assumeRole, `{"IpAddress":{"aws:SourceIp":["10.0.0.0/8","10.0.0.0/8"]},"Bool":{"aws:MultiFactorAuthPresent":"true"}}`),
	statement("", githubIssuer, githubAction, `{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}}`),
	statement("", `{"AWS":"*"}`, assumeRole, `{"StringEquals":{"aws:PrincipalAccount":["111122223333","444455556666","777788889999"]}}`),
	statement("", `{"AWS":"*"}`, assumeRole, ""),
	statement("", `{"Service":"ec2.amazonaws.com"}`, assumeRole, ""),
)

// partsDeclared is the owner the reader declares as theirs beside
// partsPolicy: one of the three accounts the condition names.
const partsDeclared = "aws:777788889999"

// wantParts are the parts of each finding of partsPolicy, read with
// partsDeclared, by the grant's issuer, the principal as written and the
// rule, each as the JSON the finding writes it.
var wantParts = map[string]map[string]string{
	"aws:sts arn:aws:iam::444455556666:root " + RuleNoExternalID: {
		"callers":   `[{"kind":"aws-account","value":"444455556666"}]`,
		"through":   `null`,
		"condition": `["aws:multifactorauthpresent=?(\"Bool\", \"aws:multifactorauthpresent\")","aws:principalaccount=\"444455556666\"","aws:sourceip=?(\"IpAddress\", \"aws:sourceip\")"]`,
		"unread":    `["bool aws:multifactorauthpresent [\"true\"]","ipaddress aws:sourceip [\"10.0.0.0/8\"]"]`,
	},
	"aws:sts * " + RuleNoExternalID: {
		"callers":   `[{"kind":"aws-account","value":"111122223333"},{"kind":"aws-account","value":"444455556666"}]`,
		"through":   `null`,
		"condition": `["aws:principalaccount=(\"111122223333\" | \"444455556666\" | \"777788889999\")"]`,
		"unread":    `[]`,
	},
	"aws:sts * " + RuleAnyAccount: {
		"callers":   `[{"kind":"platform","value":null}]`,
		"through":   `null`,
		"condition": `[]`,
		"unread":    `[]`,
	},
	"https://token.actions.githubusercontent.com arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com " + RuleNoOwner: {
		"callers":   `[{"kind":"platform","value":null}]`,
		"through":   `"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"`,
		"condition": `["aud=\"sts.amazonaws.com\""]`,
		"unread":    `[]`,
	},
}

// partsRead are the parts of each finding of an answer, by its grant's
// issuer, its principal as written and its rule, each part as the JSON the
// finding writes it, compacted; and each grant's own unread conditions by
// its number, beside every finding of the grant. A part the finding does not
// write, or a grant that writes no unread, is missing from the maps.
func partsRead(t *testing.T, answer []byte) map[string]map[string]string {
	t.Helper()
	var a struct {
		Grants []struct {
			Issuer      string `json:"issuer"`
			Populations []struct {
				Way *struct {
					Principal []struct {
						Text string `json:"text"`
					} `json:"principal"`
				} `json:"way"`
				Finding map[string]json.RawMessage `json:"finding"`
			} `json:"populations"`
		} `json:"grants"`
	}
	var grants struct {
		Grants []map[string]json.RawMessage `json:"grants"`
	}
	if err := json.Unmarshal(answer, &a); err != nil {
		t.Fatalf("not an answer: %v\n%s", err, answer)
	}
	if err := json.Unmarshal(answer, &grants); err != nil {
		t.Fatalf("not an answer: %v\n%s", err, answer)
	}
	compact := func(raw json.RawMessage) string {
		var b bytes.Buffer
		if err := json.Compact(&b, raw); err != nil {
			t.Fatalf("not JSON: %v: %s", err, raw)
		}
		return b.String()
	}
	out := map[string]map[string]string{}
	for i, g := range a.Grants {
		for _, p := range g.Populations {
			if p.Finding == nil {
				continue
			}
			principal := ""
			if p.Way != nil && len(p.Way.Principal) > 0 {
				principal = p.Way.Principal[0].Text
			}
			var rule string
			if err := json.Unmarshal(p.Finding["rule"], &rule); err != nil {
				t.Fatalf("a finding with no rule: %s", answer)
			}
			key := g.Issuer + " " + principal + " " + rule
			if _, twice := out[key]; twice {
				t.Fatalf("two findings are %s; the test cannot tell them apart", key)
			}
			parts := map[string]string{}
			for _, name := range []string{"callers", "through", "condition", "unread"} {
				if raw, written := p.Finding[name]; written {
					parts[name] = compact(raw)
				}
			}
			if raw, written := grants.Grants[i]["unread"]; written {
				parts["grant unread"] = compact(raw)
			}
			out[key] = parts
		}
	}
	return out
}

// partsHeld holds the parts of an answer's findings to wantParts: the same
// findings, each writing every part as wanted, and its grant writing the
// unread conditions the finding does.
func partsHeld(t *testing.T, name string, answer []byte) {
	t.Helper()
	got := partsRead(t, answer)
	if keys, want := slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(wantParts)); !slices.Equal(keys, want) {
		t.Fatalf("%s: the findings are\n %q\nwant\n %q", name, keys, want)
	}
	for key, want := range wantParts {
		parts := got[key]
		for _, part := range slices.Sorted(maps.Keys(want)) {
			if g, written := parts[part]; !written {
				t.Errorf("%s: %s writes no %s; want %s", name, key, part, want[part])
			} else if g != want[part] {
				t.Errorf("%s: %s writes %s %s; want %s", name, key, part, g, want[part])
			}
		}
		if g, written := parts["grant unread"]; !written || g != want["unread"] {
			t.Errorf("%s: the grant of %s writes unread %q (written: %v); want %s, as its finding does", name, key, g, written, want["unread"])
		}
	}
}

// TestFindingParts: each finding writes who the way in lets in, typed, as
// the platform whose every account holder it admits or each account it
// names that the reader has not declared, and no account the reader has;
// the provider a web-identity token comes through as the policy writes it,
// and null for an AWS principal, which comes through none; its term's
// condition, empty where it holds none; and the conditions its statement
// writes that the term does not read, each once, as its grant writes them.
func TestFindingParts(t *testing.T) {
	partsHeld(t, "read", AdmitsFor([]byte(partsPolicy), []byte(partsDeclared)))
}

// TestRemarkSaysTheFindingsPartsAgain: an answer kept with every account
// declared has no finding of an AWS account; marked again with one, the
// findings it meets now write the same parts as the policy read with that
// one does, the unread conditions included, which only the policy says.
func TestRemarkSaysTheFindingsPartsAgain(t *testing.T) {
	kept := AdmitsFor([]byte(partsPolicy), []byte("aws:111122223333\naws:444455556666\n"+partsDeclared))
	if got := partsRead(t, kept); len(got) != 2 {
		t.Fatalf("kept with every account declared, the answer has %d findings, want the two of anyone: %q", len(got), slices.Sorted(maps.Keys(got)))
	}
	again := remarkNow(kept, partsDeclared)
	if _, declined := declinedOf(again); declined {
		t.Fatalf("the answer was declined: %s", again)
	}
	partsHeld(t, "marked again", again)
	if want := AdmitsFor([]byte(partsPolicy), []byte(partsDeclared)); !bytes.Equal(again, want) {
		at := firstDifference(again, want)
		t.Errorf("marked again, the answer is not the policy's read with the same owner:\nRemark    ...%s...\nAdmitsFor ...%s...", around(again, at), around(want, at))
	}
}
