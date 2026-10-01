package ring_test

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/CloudArq-net/issuers/tenancy"

	"github.com/CloudArq-net/cloudarq/internal/registry"
	"github.com/CloudArq-net/cloudarq/internal/ring"
)

// TestTheStandInIsTheCensus: this package's corpus, its soundness oracle
// and its laws read a stand-in for the census, while the command reads the
// census itself through internal/registry, so a fact edited on one side
// alone would split what the tests prove from what the command prints.
// Every issuer the stand-in lists, and every issuer the corpus expects a
// grant of, has exactly the facts internal/registry gives it, but for
// whether the parser modelled the grant's principal: the statement answers
// that, never the census, and the stand-in reads every principal as
// modelled. An issuer the stand-in does not list is one the census has not
// surveyed.
func TestTheStandInIsTheCensus(t *testing.T) {
	listed, named := ring.StandInIssuers(), ring.CorpusIssuers()
	compared, surveyed := 0, 0
	for _, issuer := range slices.Concat(listed, named) {
		want, _ := registry.Facts(issuer)
		got := ring.CensusFacts(issuer)
		if !got.PrincipalModelled {
			t.Errorf("%q: the stand-in reads its principal as not modelled, which is the statement's to say", issuer)
		}
		got.PrincipalModelled = false
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q:\n stand-in %+v %+v\n census   %+v %+v", issuer, got, got.Tenancy, want, want.Tenancy)
		}
		compared++
		if want.IssuerKind != ring.NotSurveyed {
			surveyed++
		}
	}
	if len(listed) == 0 || len(named) == 0 || surveyed == 0 {
		t.Fatalf("%d issuers listed, %d named by the corpus, %d of them surveyed; the stand-in was held to too little", len(listed), len(named), surveyed)
	}
	t.Logf("%d issuers listed, %d named by the corpus: %d compared, %d of them surveyed", len(listed), len(named), compared, surveyed)
}

// TestTheStandInReadsTheKeysAWSDocuments: the stand-in reads a condition on
// a key exactly when the census says AWS documents it for the issuer's
// tokens, as the command does, for every issuer the stand-in lists; it
// records each key with the claims the census says AWS reads it from; it
// reads a key as multivalued exactly where the census records AWS's sentence
// saying so; and it reads a key from a claim of several values exactly where
// the census records the issuer's tokens may carry them.
func TestTheStandInReadsTheKeysAWSDocuments(t *testing.T) {
	issuers, compared, documentedKeys, multivalued, severalValues := 0, 0, 0, 0, 0
	for _, issuer := range ring.StandInIssuers() {
		var census []tenancy.ConditionKey
		if e, _, ok := tenancy.Match(string(issuer)); ok {
			census = e.AWSConditionKeys
		}
		var standIn []tenancy.ConditionKey
		var keys []string
		for _, k := range ring.AWSKeys[issuer] {
			standIn = append(standIn, tenancy.ConditionKey{Key: k.Key, Claim: k.Claim, TableClaim: k.Table, FallbackClaim: k.Fallback, Multivalued: k.Multivalued})
			keys = append(keys, k.Key, strings.ToUpper(k.Key))
		}
		if !slices.Equal(census, standIn) {
			t.Errorf("%s: the census records %+v, the stand-in reads %+v", issuer, census, standIn)
		}
		issuers++
		// the keys in another ASCII case, keys AWS does not document for
		// GitHub, a key a Unicode folding would reach, and no key at all
		probes := slices.Concat(keys, []string{"Repository_Owner_ID", "repository_owner", "enterprise", "workflow_ref", "\u017fub", ""})
		for _, key := range probes {
			documented, known := ring.StandInKeys(issuer, key)
			wantDocumented, wantKnown := registry.AWSDocumentsConditionKey(issuer, key)
			if documented != wantDocumented || known != wantKnown {
				t.Errorf("%s, %q: the stand-in answers (%v, %v), the census (%v, %v)", issuer, key, documented, known, wantDocumented, wantKnown)
			}
			if got, want := ring.StandInMultivalued(issuer, key), registry.AWSDocumentsMultivalued(issuer, key); got != want {
				t.Errorf("%s, %q: the stand-in reads the key as multivalued: %v; the census: %v", issuer, key, got, want)
			}
			if wantDocumented {
				documentedKeys++
			}
			if registry.AWSDocumentsMultivalued(issuer, key) {
				multivalued++
			}
			if got, want := ring.StandInMultiValuedClaim(issuer, key), registry.AWSReadsAMultiValuedClaim(issuer, key); got != want {
				t.Errorf("%s, %q: the stand-in reads the key from a claim of several values: %v; the census: %v", issuer, key, got, want)
			}
			if registry.AWSReadsAMultiValuedClaim(issuer, key) {
				severalValues++
			}
			compared++
		}
	}
	if issuers == 0 || documentedKeys == 0 || documentedKeys == compared || multivalued == 0 || multivalued == documentedKeys || severalValues == 0 || severalValues == documentedKeys {
		t.Fatalf("%d issuers, %d of %d probes documented, %d of them multivalued, %d read from a claim of several values; the comparison cannot tell a key read from one not read, or a key that may hold several values from another", issuers, documentedKeys, compared, multivalued, severalValues)
	}
	t.Logf("%d issuers, %d keys compared, %d of them documented, %d of those multivalued, %d read from a claim of several values", issuers, compared, documentedKeys, multivalued, severalValues)
}
