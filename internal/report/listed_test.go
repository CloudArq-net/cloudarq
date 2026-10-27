package report

import (
	"bytes"
	"cmp"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// The accounts these tests trust: two that vendors publish as their own,
// one of them on two pages, and two no vendor publishes.
const (
	datadogARN   = "arn:aws:iam::464622532012:root"
	segmentARN   = "arn:aws:iam::595280932656:root"
	unlistedARN  = "arn:aws:iam::111122223333:root"
	laterARN     = "arn:aws:iam::777788889999:root" // no vendor publishes it, and it sorts after both
	datadogPage  = "https://raw.githubusercontent.com/DataDog/cloudformation-template/master/aws/datadog_integration_role.yaml"
	datadogWords = ", which Datadog publishes as its own"
	segmentWords = ", which Segment (Twilio) publishes as its own" // on two pages, named once
)

// trustPolicy is a trust policy of the statements given, written by
// encoding/json.
func trustPolicy(t *testing.T, statements ...map[string]any) []byte {
	t.Helper()
	doc, err := json.MarshalIndent(map[string]any{"Version": "2012-10-17", "Statement": statements}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// trusting is one statement letting the principals in, each by its ARN.
// The effect is "Allow", or "allow", which the engine does not read as an
// effect, and so places what the statement admits as could rather than can.
func trusting(effect string, principals ...string) map[string]any {
	return map[string]any{"Effect": effect, "Principal": map[string]any{"AWS": principals}, "Action": "sts:AssumeRole"}
}

// ringSentence is the sentence of the answer's ring at place, or "" when
// no grant is in it.
func ringSentence(a Answer, place string) string {
	for _, r := range a.Rings {
		if r.Place == place && len(r.GrantNumbers) > 0 {
			return r.Sentence
		}
	}
	return ""
}

// whoSentences are what each grant's way says of who it lets in, by grant.
func whoSentences(a Answer) []string {
	var who []string
	for _, g := range a.Grants {
		for _, p := range g.Populations {
			if p.Way != nil && p.Way.Who != nil {
				who = append(who, p.Way.Who.Sentence)
			}
		}
	}
	return who
}

// TestAListedAccountIsNamedInEverySentenceThatNamesIt: an AWS account a
// vendor publishes as its own is named with the vendor, once, however many
// pages publish it, wherever a sentence names the account by itself: in
// the ring's sentence beside the owners it names, and in the way's who; two
// vendors in one sentence are each named after their own account. An
// owner counted rather than named is not, and nothing moves: the ring, the
// headline and the questions are the ones the account would have unlisted.
func TestAListedAccountIsNamedInEverySentenceThatNamesIt(t *testing.T) {
	for _, c := range []struct {
		name       string
		doc        []byte
		owners     string
		recognised string // the account a scan read, recognised as the reader's
		headline   string
		rings      map[string]string
		who        []string
	}{
		{
			name:     "two listed outsiders",
			doc:      trustPolicy(t, trusting("Allow", datadogARN, segmentARN)),
			headline: "A named outsider can assume this role.",
			rings: map[string]string{
				"outsider": "aws:464622532012" + datadogWords + ", and aws:595280932656" + segmentWords + ", can assume this role and are not declared as yours.",
			},
			who: []string{
				"aws:464622532012" + datadogWords + ", can assume this role and is not declared as yours.",
				"aws:595280932656" + segmentWords + ", can assume this role and is not declared as yours.",
			},
		},
		{
			name:     "two listed, both declared",
			doc:      trustPolicy(t, trusting("Allow", datadogARN, segmentARN)),
			owners:   "aws:464622532012\naws:595280932656",
			headline: "Nothing outside your company can assume this role.",
			rings: map[string]string{
				"yours": "aws:464622532012, declared as yours" + datadogWords + ", and aws:595280932656, declared as yours" + segmentWords + ", can assume this role.",
			},
			who: []string{
				"aws:464622532012, declared as yours" + datadogWords + ", can assume this role.",
				"aws:595280932656, declared as yours" + segmentWords + ", can assume this role.",
			},
		},
		{
			// The listed account is named first, each said to be the
			// reader's on its own: after "aws:111122223333 and
			// aws:464622532012, declared as yours", the vendor would read
			// as said of both.
			name:     "two declared, the second listed",
			doc:      trustPolicy(t, trusting("Allow", datadogARN, unlistedARN)),
			owners:   "aws:464622532012\naws:111122223333",
			headline: "Nothing outside your company can assume this role.",
			rings: map[string]string{
				"yours": "aws:464622532012, declared as yours" + datadogWords + ", and aws:111122223333, declared as yours, can assume this role.",
			},
			who: []string{
				"aws:111122223333, declared as yours, can assume this role.",
				"aws:464622532012, declared as yours" + datadogWords + ", can assume this role.",
			},
		},
		{
			name:     "two declared, the first listed",
			doc:      trustPolicy(t, trusting("Allow", datadogARN, laterARN)),
			owners:   "aws:464622532012\naws:777788889999",
			headline: "Nothing outside your company can assume this role.",
			rings: map[string]string{
				"yours": "aws:464622532012, declared as yours" + datadogWords + ", and aws:777788889999, declared as yours, can assume this role.",
			},
			who: []string{
				"aws:464622532012, declared as yours" + datadogWords + ", can assume this role.",
				"aws:777788889999, declared as yours, can assume this role.",
			},
		},
		{
			name:       "listed and recognised",
			doc:        trustPolicy(t, trusting("Allow", datadogARN)),
			recognised: "464622532012",
			headline:   "Nothing outside your company can assume this role.",
			rings: map[string]string{
				"yours": "aws:464622532012, recognised: the account this scan read" + datadogWords + ", can assume this role.",
			},
			who: []string{"aws:464622532012, recognised: the account this scan read" + datadogWords + ", can assume this role."},
		},
		{
			name:       "one recognised and one declared, both listed",
			doc:        trustPolicy(t, trusting("Allow", datadogARN, segmentARN)),
			owners:     "aws:595280932656",
			recognised: "464622532012",
			headline:   "Nothing outside your company can assume this role.",
			rings: map[string]string{
				"yours": "aws:464622532012, recognised: the account this scan read" + datadogWords + ", and aws:595280932656, declared as yours" + segmentWords + ", can assume this role.",
			},
			who: []string{
				"aws:464622532012, recognised: the account this scan read" + datadogWords + ", can assume this role.",
				"aws:595280932656, declared as yours" + segmentWords + ", can assume this role.",
			},
		},
		{
			name:     "a listed outsider that could assume the role",
			doc:      trustPolicy(t, trusting("allow", datadogARN)),
			headline: "A named outsider could assume this role.",
			rings: map[string]string{
				"outsider": "aws:464622532012" + datadogWords + ", could assume this role and is not declared as yours.",
			},
			who: []string{"aws:464622532012" + datadogWords + ", could assume this role and is not declared as yours."},
		},
		{
			name:     "an unlisted outsider that can, a listed one that could",
			doc:      trustPolicy(t, trusting("Allow", unlistedARN), trusting("allow", datadogARN)),
			headline: "A named outsider can assume this role.",
			rings: map[string]string{
				"outsider": "aws:111122223333 can assume this role, and aws:464622532012" + datadogWords + ", could; neither is declared as yours.",
			},
			who: []string{
				"aws:111122223333 can assume this role and is not declared as yours.",
				"aws:464622532012" + datadogWords + ", could assume this role and is not declared as yours.",
			},
		},
		{
			name:     "a listed outsider that can, another that could",
			doc:      trustPolicy(t, trusting("Allow", datadogARN), trusting("allow", segmentARN)),
			headline: "A named outsider can assume this role.",
			rings: map[string]string{
				"outsider": "aws:464622532012" + datadogWords + ", can assume this role, and aws:595280932656" + segmentWords + ", could; neither is declared as yours.",
			},
			who: []string{
				"aws:464622532012" + datadogWords + ", can assume this role and is not declared as yours.",
				"aws:595280932656" + segmentWords + ", could assume this role and is not declared as yours.",
			},
		},
		{
			name:     "a declared listed account that could assume the role",
			doc:      trustPolicy(t, trusting("allow", datadogARN)),
			owners:   "aws:464622532012",
			headline: "Your AWS accounts could assume this role.",
			rings: map[string]string{
				"yours": "aws:464622532012, declared as yours" + datadogWords + ", could assume this role.",
			},
			who: []string{"aws:464622532012, declared as yours" + datadogWords + ", could assume this role."},
		},
		{
			name:     "two declared listed accounts, one that can and one that could",
			doc:      trustPolicy(t, trusting("Allow", datadogARN), trusting("allow", segmentARN)),
			owners:   "aws:464622532012\naws:595280932656",
			headline: "Nothing outside your company can assume this role.",
			rings: map[string]string{
				"yours": "aws:464622532012, declared as yours" + datadogWords + ", can assume this role, and aws:595280932656" + segmentWords + ", could.",
			},
			who: []string{
				"aws:464622532012, declared as yours" + datadogWords + ", can assume this role.",
				"aws:595280932656, declared as yours" + segmentWords + ", could assume this role.",
			},
		},
		{
			// One id written in two partitions is two accounts with one
			// name, and the vendor publishes one of them: the ring names
			// the account once, and so names no vendor; each way names its
			// own account.
			name:     "the listed id in two partitions",
			doc:      trustPolicy(t, trusting("Allow", datadogARN, "arn:aws-us-gov:iam::464622532012:root")),
			headline: "A named outsider can assume this role.",
			rings: map[string]string{
				"outsider": "aws:464622532012 can assume this role and is not declared as yours.",
			},
			who: []string{
				"aws:464622532012" + datadogWords + ", can assume this role and is not declared as yours.",
				"aws:464622532012 can assume this role and is not declared as yours.",
			},
		},
		{
			name:     "three outsiders, counted",
			doc:      trustPolicy(t, trusting("Allow", datadogARN, segmentARN, unlistedARN)),
			headline: "A named outsider can assume this role.",
			rings: map[string]string{
				"outsider": "3 named outsiders can assume this role; none is declared as yours.",
			},
			who: []string{
				"aws:111122223333 can assume this role and is not declared as yours.",
				"aws:464622532012" + datadogWords + ", can assume this role and is not declared as yours.",
				"aws:595280932656" + segmentWords + ", can assume this role and is not declared as yours.",
			},
		},
		{
			name:     "one listed outsider, one listed account declared",
			doc:      trustPolicy(t, trusting("Allow", datadogARN, segmentARN)),
			owners:   "aws:595280932656",
			headline: "A named outsider can assume this role.",
			rings: map[string]string{
				"outsider": "aws:464622532012" + datadogWords + ", can assume this role and is not declared as yours.",
				"yours":    "aws:595280932656, declared as yours" + segmentWords + ", can assume this role.",
			},
			who: []string{
				"aws:464622532012" + datadogWords + ", can assume this role and is not declared as yours.",
				"aws:595280932656, declared as yours" + segmentWords + ", can assume this role.",
			},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := AnswerFor(c.doc, []byte(c.owners))
			if c.recognised != "" {
				a = admitsRecognising(c.doc, []byte(c.owners), Bundle{Account: c.recognised}.recognised())
			}
			if a.Error != "" {
				t.Fatalf("the policy was not read: %s", a.Error)
			}
			if a.Headline == nil || a.Headline.Sentence != c.headline {
				t.Errorf("headline %+v, want %q", a.Headline, c.headline)
			}
			for place, want := range c.rings {
				if got := ringSentence(a, place); got != want {
					t.Errorf("the %s ring says\n  %q\nwant\n  %q", place, got, want)
				}
			}
			if got := whoSentences(a); !slices.Equal(got, c.who) {
				t.Errorf("the ways say who\n  %q\nwant\n  %q", got, c.who)
			}
			// Each sentence's spans are the sentence: the vendor is in the
			// words a page renders as well as the line the command prints.
			for _, r := range a.Rings {
				if plain(r.Spans) != r.Sentence {
					t.Errorf("the %s ring's spans read %q, its sentence %q", r.Place, plain(r.Spans), r.Sentence)
				}
			}
			for _, q := range questionsOf(a) {
				if !strings.HasPrefix(q, "Is aws:") || strings.Contains(q, "publishes") {
					t.Errorf("a question names the vendor or asks something else: %q", q)
				}
			}
		})
	}
}

// TestOfTwoOwnersTheListedOneIsNamedFirst: of two owners named one by one,
// one an account a vendor publishes and the other one no vendor does, the
// listed account is named first and the vendor right after it, so that the
// vendor is said of that account alone: said after the second, it reads as
// said of both, and the account no vendor publishes reads as the vendor's.
// It holds whichever account the policy writes first, in one statement or
// in two, declared, recognised or neither, and for the role in a bundle.
func TestOfTwoOwnersTheListedOneIsNamedFirst(t *testing.T) {
	const (
		outsiders = "aws:464622532012" + datadogWords + ", and aws:111122223333 can assume this role and are not declared as yours."
		declared  = "aws:464622532012, declared as yours" + datadogWords + ", and aws:111122223333, declared as yours, can assume this role."
	)
	docs := map[string][]byte{
		"one statement, the listed account first":   trustPolicy(t, trusting("Allow", datadogARN, unlistedARN)),
		"one statement, the listed account second":  trustPolicy(t, trusting("Allow", unlistedARN, datadogARN)),
		"two statements, the listed account first":  trustPolicy(t, trusting("Allow", datadogARN), trusting("Allow", unlistedARN)),
		"two statements, the listed account second": trustPolicy(t, trusting("Allow", unlistedARN), trusting("Allow", datadogARN)),
	}
	for _, c := range []struct {
		owners     string
		recognised string // the account a scan read; "" reads one no grant here pins
		place      string
		want       string
	}{
		{"", "", "outsider", outsiders},
		{"aws:111122223333\naws:464622532012", "", "yours", declared},
		{"aws:464622532012\naws:111122223333", "", "yours", declared},
		{"aws:464622532012", "111122223333", "yours", "aws:464622532012, declared as yours" + datadogWords + ", and aws:111122223333, recognised: the account this scan read, can assume this role."},
		{"aws:111122223333", "464622532012", "yours", "aws:464622532012, recognised: the account this scan read" + datadogWords + ", and aws:111122223333, declared as yours, can assume this role."},
	} {
		for name, doc := range docs {
			a := AnswerFor(doc, []byte(c.owners))
			if c.recognised != "" {
				a = admitsRecognising(doc, []byte(c.owners), Bundle{Account: c.recognised}.recognised())
			}
			if got := ringSentence(a, c.place); got != c.want {
				t.Errorf("%s, owners %q, %q recognised: the %s ring says\n  %q\nwant\n  %q", name, c.owners, c.recognised, c.place, got, c.want)
			}
			read := cmp.Or(c.recognised, bundleAccount)
			f := findingsOf(t, oneRoleBundle(t, doc, read, "", ""), c.owners)
			if len(f.Roles) != 1 {
				t.Fatalf("%s: the bundle's answers are %d roles, want 1", name, len(f.Roles))
			}
			if got := ringSentence(answerOf(t, f.Roles[0].Answer), c.place); got != c.want {
				t.Errorf("%s, owners %q, a bundle read from %s: the %s ring says\n  %q\nwant\n  %q", name, c.owners, read, c.place, got, c.want)
			}
		}
	}
}

// questionsOf is every question the rings ask.
func questionsOf(a Answer) []string {
	var qs []string
	for _, r := range a.Rings {
		for _, q := range r.Questions {
			qs = append(qs, q.Sentence)
		}
	}
	return qs
}

// listedOwner is an owner as a consumer reads it from the answer's JSON,
// with the member a listed account carries.
type listedOwner struct {
	Value    string `json:"value"`
	Declared bool   `json:"declared"`
	Listed   *struct {
		Vendor string `json:"vendor"`
		Uses   []struct {
			Use     string `json:"use"`
			Source  string `json:"source"`
			Checked string `json:"checked"`
		} `json:"uses"`
	} `json:"listed"`
}

// ownersInJSON are the owners of every population of the answer's JSON, in
// the order of its grants.
func ownersInJSON(t *testing.T, answer []byte) []listedOwner {
	t.Helper()
	var read struct {
		Grants []struct {
			Populations []struct {
				Owners []listedOwner `json:"owners"`
			} `json:"populations"`
		} `json:"grants"`
	}
	if err := json.Unmarshal(answer, &read); err != nil {
		t.Fatal(err)
	}
	var owners []listedOwner
	for _, g := range read.Grants {
		for _, p := range g.Populations {
			owners = append(owners, p.Owners...)
		}
	}
	return owners
}

// TestAListedOwnerCarriesItsVendorInTheJSON: the owner a listed account is
// carries listed, its vendor and each use with the page and the date it was
// read, in the list's order, declared or not; an owner no vendor publishes
// carries no listed member at all.
func TestAListedOwnerCarriesItsVendorInTheJSON(t *testing.T) {
	doc := trustPolicy(t, trusting("Allow", datadogARN, segmentARN, unlistedARN))
	for _, owners := range []string{"", "aws:464622532012\naws:595280932656\naws:111122223333"} {
		got := ownersInJSON(t, AdmitsFor(doc, []byte(owners)))
		if len(got) != 3 {
			t.Fatalf("owners %q: %d owners in the answer, want 3", owners, len(got))
		}
		for _, o := range got {
			if o.Declared != (owners != "") {
				t.Errorf("owners %q: %s is declared %v", owners, o.Value, o.Declared)
			}
			switch o.Value {
			case "111122223333":
				if o.Listed != nil {
					t.Errorf("owners %q: an account no vendor publishes carries listed %+v", owners, *o.Listed)
				}
			case "464622532012":
				if o.Listed == nil || o.Listed.Vendor != "Datadog" || len(o.Listed.Uses) != 1 ||
					o.Listed.Uses[0].Use != "AWS integration (role delegation)" || o.Listed.Uses[0].Source != datadogPage || o.Listed.Uses[0].Checked != "2026-10-19" {
					t.Errorf("owners %q: Datadog's account carries listed %+v", owners, o.Listed)
				}
			case "595280932656":
				if o.Listed == nil || o.Listed.Vendor != "Segment (Twilio)" || len(o.Listed.Uses) != 2 ||
					o.Listed.Uses[0].Use != "AWS S3 with IAM Role Support storage destination" || o.Listed.Uses[1].Use != "Amazon Kinesis destination" ||
					o.Listed.Uses[0].Source != "https://www.twilio.com/docs/segment/connections/storage/catalog/aws-s3" ||
					o.Listed.Uses[1].Source != "https://www.twilio.com/docs/segment/connections/destinations/catalog/amazon-kinesis" {
					t.Errorf("owners %q: Segment's account carries listed %+v", owners, o.Listed)
				}
			default:
				t.Errorf("owners %q: an owner no grant here names: %s", owners, o.Value)
			}
		}
	}
	if unlisted := AdmitsFor(trustPolicy(t, trusting("Allow", unlistedARN)), nil); bytes.Contains(unlisted, []byte(`"listed"`)) {
		t.Errorf("an answer that names no listed account writes listed:\n%s", unlisted)
	}
}

// TestARemarkedAnswerNamesTheVendor: an answer a scan kept, re-marked with
// an owner declared now, is the answer the policy gives with that owner,
// the vendor named in it; and re-marked with no owner it is the answer as
// it was kept.
func TestARemarkedAnswerNamesTheVendor(t *testing.T) {
	doc := trustPolicy(t, trusting("Allow", datadogARN, unlistedARN))
	kept := Admits(doc)
	if !bytes.Contains(kept, []byte(`"listed":{"vendor":"Datadog"`)) {
		t.Fatalf("the kept answer names no vendor:\n%s", kept)
	}
	if got := Remark(kept, nil, thisBuild, thisBuild); !bytes.Equal(got, kept) {
		t.Errorf("re-marked with no owner, the answer moved at byte %d", firstDifference(got, kept))
	}
	owners := []byte("aws:464622532012")
	got, want := Remark(kept, owners, thisBuild, thisBuild), AdmitsFor(doc, owners)
	if !bytes.Equal(got, want) {
		t.Fatalf("re-marked with %s, the answer is not AdmitsFor's: they part at byte %d\n%s", owners, firstDifference(got, want), got)
	}
	declared := `"sentence":"aws:464622532012, declared as yours` + datadogWords + `, can assume this role."`
	if !bytes.Contains(got, []byte(declared)) {
		t.Errorf("re-marked with %s, the answer does not say %s\n%s", owners, declared, got)
	}
}

// TestExplainNamesEachPageAListedAccountIsOn: --explain gives, under the
// principal as written, each page the vendor publishes the account on, as
// fields: the account, the vendor, what the page says the account is used
// for, the page and the date it was read; and gives none for an account no
// vendor publishes.
func TestExplainNamesEachPageAListedAccountIsOn(t *testing.T) {
	a := AnswerFor(trustPolicy(t, trusting("Allow", datadogARN, segmentARN, unlistedARN)), nil)
	var listed []string
	for _, line := range a.ExplainWays("") {
		if l, ok := strings.CutPrefix(strings.TrimLeft(line, " "), "listed "); ok {
			listed = append(listed, l)
		}
	}
	want := []string{
		"aws:464622532012 · Datadog · AWS integration (role delegation) · " + datadogPage + " · checked 2026-10-19",
		"aws:595280932656 · Segment (Twilio) · AWS S3 with IAM Role Support storage destination · https://www.twilio.com/docs/segment/connections/storage/catalog/aws-s3 · checked 2026-10-19",
		"aws:595280932656 · Segment (Twilio) · Amazon Kinesis destination · https://www.twilio.com/docs/segment/connections/destinations/catalog/amazon-kinesis · checked 2026-10-19",
	}
	if !slices.Equal(listed, want) {
		t.Errorf("--explain lists\n  %q\nwant\n  %q", listed, want)
	}
}
