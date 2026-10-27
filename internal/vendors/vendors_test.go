package vendors

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"slices"
	"testing"
)

// listSHA256 is the digest of aws-accounts.json as it was copied. A row
// added, dropped or edited here changes it: the list changes only by
// copying the file again, and this digest moves in the same commit.
const listSHA256 = "3330e56ee5353f7150d14767a7bf956f8611afca0c3a71544db8752d4ed075df"

// listRows is how many accounts the copied file holds.
const listRows = 108

var (
	accountID = regexp.MustCompile(`^[0-9]{12}$`)
	date      = regexp.MustCompile(`^20[0-9]{2}-[01][0-9]-[0-3][0-9]$`)
)

// TestTheListIsTheFileAsCopied holds the embedded file to the digest it was
// copied with, and reads it with every field the file writes known: a field
// the types do not carry would be dropped without a word, so it fails here.
func TestTheListIsTheFileAsCopied(t *testing.T) {
	if sum := sha256.Sum256(list); hex.EncodeToString(sum[:]) != listSHA256 {
		t.Fatalf("aws-accounts.json has sha256 %x, not %s, the file as copied", sum, listSHA256)
	}
	dec := json.NewDecoder(bytes.NewReader(list))
	dec.DisallowUnknownFields()
	var rows []Account
	if err := dec.Decode(&rows); err != nil {
		t.Fatalf("the list does not read with the fields Account and Source carry: %v", err)
	}
	if dec.More() {
		t.Fatal("the list holds more than one JSON value")
	}
	if len(rows) != listRows {
		t.Fatalf("the list holds %d accounts, want %d", len(rows), listRows)
	}
	parsed, err := parse(list)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed) != len(rows) {
		t.Fatalf("parse read %d accounts of %d", len(parsed), len(rows))
	}
}

// TestEveryRowIsWhole: each row names a vendor, one twelve-digit account in
// one of the three partitions, once, and at least one page, each with what
// the account is used for, an address the page is read at and the date it
// was read; a date the page carries itself is a date too. Every row is
// found by Lookup in its own partition.
func TestEveryRowIsWhole(t *testing.T) {
	rows, err := parse(list)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[[2]string]bool{}
	sources := 0
	for i, r := range rows {
		at := r.Partition + ":" + r.Account
		if r.Vendor == "" {
			t.Errorf("row %d (%s) names no vendor", i, at)
		}
		if !accountID.MatchString(r.Account) {
			t.Errorf("row %d: %q is not a twelve-digit account id", i, r.Account)
		}
		if !slices.Contains([]string{"aws", "aws-us-gov", "aws-cn"}, r.Partition) {
			t.Errorf("row %d (%s): %q is not a partition", i, r.Account, r.Partition)
		}
		if key := [2]string{r.Partition, r.Account}; seen[key] {
			t.Errorf("row %d: %s is listed twice", i, at)
		} else {
			seen[key] = true
		}
		if len(r.Sources) == 0 {
			t.Errorf("row %d (%s) has no source", i, at)
		}
		for _, s := range r.Sources {
			sources++
			if s.Use == "" || len(s.URL) <= len("https://") || s.URL[:len("https://")] != "https://" || !date.MatchString(s.Checked) || s.Dated != "" && !date.MatchString(s.Dated) {
				t.Errorf("row %d (%s): source %+v is not whole", i, at, s)
			}
		}
		got, ok := Lookup(r.Partition, r.Account)
		if !ok || got.Vendor != r.Vendor || !slices.Equal(got.Sources, r.Sources) {
			t.Errorf("Lookup(%q, %q) = %+v, %v; want row %d", r.Partition, r.Account, got, ok, i)
		}
	}
	if sources < len(rows) {
		t.Fatalf("%d sources over %d rows; the check examined too little", sources, len(rows))
	}
}

// TestLookup: an account is found in the partition the list holds it in
// and in no other, and an id the list does not hold is found nowhere.
func TestLookup(t *testing.T) {
	for _, c := range []struct {
		partition, account string
		vendor             string // empty when the account is not found
	}{
		{"aws", "464622532012", "Datadog"},
		{"aws-us-gov", "044793339203", "Databricks"},
		{"aws-cn", "211784309483", "Prisma Cloud (Palo Alto Networks)"},
		// the same digits in another partition are another account
		{"aws-us-gov", "464622532012", ""},
		{"aws-cn", "464622532012", ""},
		{"aws", "044793339203", ""},
		// a partition is matched as written, and an id as a whole id
		{"", "464622532012", ""},
		{"AWS", "464622532012", ""},
		{"aws", "46462253201", ""},
		{"aws", " 464622532012", ""},
		// an account no vendor publishes
		{"aws", "111122223333", ""},
	} {
		got, ok := Lookup(c.partition, c.account)
		if ok != (c.vendor != "") || got.Vendor != c.vendor {
			t.Errorf("Lookup(%q, %q) = %q, %v; want %q", c.partition, c.account, got.Vendor, ok, c.vendor)
			continue
		}
		if ok && (got.Partition != c.partition || got.Account != c.account || len(got.Sources) == 0) {
			t.Errorf("Lookup(%q, %q) = %+v", c.partition, c.account, got)
		}
	}
	datadog, _ := Lookup("aws", "464622532012")
	want := []Source{{Use: "AWS integration (role delegation)", URL: "https://raw.githubusercontent.com/DataDog/cloudformation-template/master/aws/datadog_integration_role.yaml", Checked: "2026-10-19"}}
	if !slices.Equal(datadog.Sources, want) {
		t.Errorf("Datadog's sources are %+v, want %+v", datadog.Sources, want)
	}
	stitch, _ := Lookup("aws", "218546966473")
	if len(stitch.Sources) != 2 || stitch.Sources[0].Use != "Amazon S3 destination, North America pipeline (us-east-1)" || stitch.Sources[1].Dated != "2026-10-15" {
		t.Errorf("an account on two pages keeps both, in the file's order, with the date each page carries: %+v", stitch.Sources)
	}
}

// TestLookupGivesACopy: what Lookup returns is the caller's, so changing it
// changes nothing the next call finds.
func TestLookupGivesACopy(t *testing.T) {
	first, _ := Lookup("aws", "464622532012")
	first.Sources[0].Use = "changed"
	if again, _ := Lookup("aws", "464622532012"); again.Sources[0].Use != "AWS integration (role delegation)" {
		t.Fatalf("a change to one result reached the list: %q", again.Sources[0].Use)
	}
}

// TestAListThatDoesNotReadNamesNothing: parse refuses what is not the
// list's shape, and a list that does not read finds no account, which says
// nothing about any account rather than something wrong.
func TestAListThatDoesNotReadNamesNothing(t *testing.T) {
	for _, raw := range []string{"", "not json", `{"vendor":"x"}`, `[{"account":5}]`} {
		if rows, err := parse([]byte(raw)); err == nil || rows != nil {
			t.Errorf("parse(%q) = %v, %v; want an error and no rows", raw, rows, err)
		}
	}
	if found := find(nil, "aws", "464622532012"); found >= 0 {
		t.Errorf("an empty list found row %d", found)
	}
}
