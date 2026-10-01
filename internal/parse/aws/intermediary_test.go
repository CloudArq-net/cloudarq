package aws

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// readOn is the form of the date a sentence was read.
var readOn = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// TestTheIntermediariesAreData holds the table to what its rows are for:
// each names one service, in the lower case its issuer is folded to, says
// who it acts for in both lengths, and rests on at least one sentence of
// AWS's, quoted from AWS's documentation with the date it was read, with
// nothing in it a terminal acts on, and so does each sentence on the other
// uses AWS documents for it. The five services the table lists are each
// there once. Transfer Family acts with the session, so its row does not
// say it passes it on.
func TestTheIntermediariesAreData(t *testing.T) {
	table := Intermediaries()
	if len(table) != len(intermediaries) {
		t.Fatalf("Intermediaries gives %d rows of a table of %d", len(table), len(intermediaries))
	}
	var services []string
	for _, row := range table {
		if row.Service == "" || row.Service != fold(row.Service) || !namesAHost(row.Service) {
			t.Errorf("%q: a service principal is written in ASCII lower case, as its issuer is folded", row.Service)
		}
		if slices.Contains(services, row.Service) {
			t.Errorf("%s: listed twice", row.Service)
		}
		services = append(services, row.Service)
		if row.ActsFor == "" || row.ActsForInFull == "" {
			t.Errorf("%s: says for whom it acts in %q and %q; both are needed", row.Service, row.ActsFor, row.ActsForInFull)
		}
		// none of the sentences the table quotes confines a service to
		// callers outside AWS: where AWS writes of workloads outside AWS, it
		// says where a service is meant to be used, not who can use it
		if strings.Contains(row.ActsFor+" "+row.ActsForInFull, "outside AWS") {
			t.Errorf("%s: says it acts for %q, %q; AWS limits no service in the table to callers outside AWS", row.Service, row.ActsFor, row.ActsForInFull)
		}
		if len(row.Sentences) == 0 {
			t.Errorf("%s: rests on no sentence of AWS's", row.Service)
		}
		for _, c := range row.Citations() {
			if c.Quote == "" || !strings.HasPrefix(c.Source, "https://docs.aws.amazon.com/") || !readOn.MatchString(c.Read) {
				t.Errorf("%s: the sentence %q on %q, read %q, is not a quote from AWS's documentation with the date it was read", row.Service, c.Quote, c.Source, c.Read)
			}
			if strings.ContainsFunc(c.Quote+c.Source, func(r rune) bool { return r < 0x20 || r >= 0x7f && r <= 0x9f }) {
				t.Errorf("%s: the sentence %q holds a control character", row.Service, c.Quote)
			}
		}
	}
	for _, want := range []string{"rolesanywhere.amazonaws.com", "credentials.iot.amazonaws.com", "ssm.amazonaws.com", "pods.eks.amazonaws.com", "transfer.amazonaws.com"} {
		if !slices.Contains(services, want) {
			t.Errorf("%s is not in the table", want)
		}
	}
	// the Pod Identity Agent also runs on EKS Hybrid Nodes, on premises, so
	// the row's words name no place and it quotes nothing that confines
	// the pods to Amazon EC2
	if eks, ok := IntermediaryOf("pods.eks.amazonaws.com"); ok {
		for _, c := range eks.Citations() {
			if strings.Contains(c.Quote, "EC2") {
				t.Errorf("pods.eks.amazonaws.com rests on %q, which AWS's pages on EKS Hybrid Nodes contradict", c.Quote)
			}
		}
	} else {
		t.Error("pods.eks.amazonaws.com is not in the table")
	}
	if transfer, ok := IntermediaryOf("transfer.amazonaws.com"); !ok || strings.Contains(transfer.ActsForInFull, "pass") {
		t.Errorf("Transfer Family acts with the session, and its row says %q", transfer.ActsForInFull)
	}
	// AWS documents Systems Manager assuming roles for maintenance windows
	// and Automation, and Transfer Family for its servers' invocation and
	// logging and its workflows, beside the use each row names
	for _, service := range []string{"ssm.amazonaws.com", "transfer.amazonaws.com"} {
		if row, ok := IntermediaryOf(service); !ok || !row.HasOtherUses() {
			t.Errorf("%s: AWS documents it assuming roles for other uses, and its row records none", service)
		}
	}
	if len(services) < 5 {
		t.Fatalf("%d services in the table; the rules above held over too little", len(services))
	}
}

// TestAnIntermediaryIsFoundInAnyCase: a service principal is a DNS name, so
// the table is read under the folding its issuer takes; a spelling no row
// holds, a partition's suffix or a region among them, finds none.
func TestAnIntermediaryIsFoundInAnyCase(t *testing.T) {
	for _, c := range []struct {
		service string
		found   bool
	}{
		{"rolesanywhere.amazonaws.com", true},
		{"RolesAnywhere.amazonaws.com", true},
		{"TRANSFER.AMAZONAWS.COM", true},
		{"rolesanywhere.amazonaws.com.cn", false},
		{"ssm.us-east-1.amazonaws.com", false},
		{"sns.amazonaws.com", false},
		{"", false},
	} {
		row, ok := IntermediaryOf(c.service)
		if ok != c.found || ok && row.Service != fold(c.service) {
			t.Errorf("%q: found %q, %v; want %v", c.service, row.Service, ok, c.found)
		}
	}
}
