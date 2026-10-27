// Package vendors is the list of AWS accounts that vendors publish as their
// own, each with what the vendor says it uses the account for: a role that
// trusts one of them trusts that vendor.
//
// The list is aws-accounts.json. Every row in it is confirmed by the
// vendor's own page or by a file in a repository the vendor owns. Each row
// names the vendor, the account's id and its partition, and each page that
// confirms it: what the vendor uses the account for, the page's address,
// the date it was read, and the date the page carries where it carries
// one. The candidates were first gathered from known_aws_accounts,
// https://github.com/fwdcloudsec/known_aws_accounts, as NOTICE says; a
// candidate is a row only once its vendor's own page confirms it.
//
// The file is copied whole and never edited here: a row is added, dropped
// or changed by copying the file again, and the digest its test holds it to
// changes with it.
//
// An account is found by its partition and its id together. The same
// twelve digits in another partition are another account, whose IAM is the
// other partition's, and the list does not name it.
package vendors

import (
	_ "embed"
	"encoding/json"
	"slices"
	"sync"
)

//go:embed aws-accounts.json
var list []byte

// Account is one row of the list: an AWS account a vendor publishes as its
// own, and the pages it does so on, in the list's order.
type Account struct {
	Vendor    string   `json:"vendor"`
	Account   string   `json:"account"`
	Partition string   `json:"partition"`
	Sources   []Source `json:"sources"`
}

// Source is one page that publishes an account: what the vendor uses it
// for, the page, the date it was read, and the date the page itself
// carries, empty where it carries none.
type Source struct {
	Use     string `json:"use"`
	URL     string `json:"url"`
	Checked string `json:"checked"`
	Dated   string `json:"dated,omitempty"`
}

var (
	read sync.Once
	rows []Account
)

// Lookup is the row of the account with this id in this partition, both as
// AWS writes them: a partition is aws, aws-us-gov or aws-cn, and an id is
// its twelve digits. ok is false for an account the list does not hold. The
// list is read on the first call, and a list that does not read holds no
// account. The row returned is the caller's own.
func Lookup(partition, account string) (Account, bool) {
	read.Do(func() { rows, _ = parse(list) })
	i := find(rows, partition, account)
	if i < 0 {
		return Account{}, false
	}
	a := rows[i]
	a.Sources = slices.Clone(a.Sources)
	return a, true
}

// find is the index of the row of the account in the partition, or -1.
func find(rows []Account, partition, account string) int {
	return slices.IndexFunc(rows, func(a Account) bool { return a.Partition == partition && a.Account == account })
}

// parse reads the list. It returns no rows with an error, so that a list
// that does not read names nobody rather than some of it.
func parse(raw []byte) ([]Account, error) {
	var out []Account
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}
