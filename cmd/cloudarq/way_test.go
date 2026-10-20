package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// oneAccount trusts one account by its root ARN, in a statement with a Sid
// and no condition, on one line.
const oneAccount = `{"Version":"2012-10-17","Statement":[{"Sid":"Partner","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"}]}`

// With --explain, once the command has answered, each grant says of each of
// its populations who it is, the principal as the statement writes it, how
// the policy lets it in and what the answer asks of it, on standard error;
// the answer on standard output is the answer without --explain, and
// without --explain nothing is written to standard error.
func TestExplainSaysWhoAndHowOfEachPopulation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "partner.json")
	if err := os.WriteFile(path, []byte(oneAccount), 0o600); err != nil {
		t.Fatal(err)
	}
	lines := []string{
		"cloudarq admits, who and how:",
		"  grant 1",
		"    who  aws:111122223333 can assume this role and is not declared as yours.",
		"         written arn:aws:iam::111122223333:root at line 1 Principal.AWS",
		`    how  Statement 1 ("Partner"), line 1, names this account, with no condition.`,
		"    ask  aws:111122223333 · Is aws:111122223333 yours?",
	}
	explained, plain := ask(t, "--explain", path), ask(t, path)
	if explained.code != 0 || plain.code != 0 {
		t.Fatalf("exit %d and %d, %s", explained.code, plain.code, explained.stderr)
	}
	if want := "\n" + strings.Join(lines, "\n") + "\n"; !strings.Contains(explained.stderr, want) {
		t.Errorf("--explain does not say who and how:\n%s\nwant the lines\n%s", explained.stderr, want)
	}
	if explained.stdout != plain.stdout || plain.stderr != "" {
		t.Errorf("--explain changed the answer, or without it the command wrote to standard error:\n%s", plain.stderr)
	}
}

// For a bundle, each role's grants say who and how under the role's name,
// and the management account of the bundle's AWS Organization and the
// Organization itself are asked about in the words the findings ask them
// in; any other owner as the answer asks it.
func TestExplainAsksOfTheOrganizationInTheFindingsWords(t *testing.T) {
	path, owners := bundleCase(t, "04-member-account")
	got := ask(t, append(append([]string{"--explain"}, owners...), "--bundle", path)...)
	if got.code != 0 {
		t.Fatalf("exit %d, %s", got.code, got.stderr)
	}
	for _, line := range []string{
		`cloudarq admits, who and how, for the role "OrganizationAccountAccessRole":`,
		"    ask  aws:111122223333 · Is this account, which manages your AWS Organization, yours? A reseller or a managed service provider may run it.",
		"    ask  aws:o-exampleorgid · Is every account in this AWS Organization yours?",
		"    ask  aws:444455556666 · Is aws:444455556666 yours?",
	} {
		if !strings.Contains(got.stderr, "\n"+line+"\n") {
			t.Errorf("the bundle's roles do not say %q:\n%s", line, got.stderr)
		}
	}
	if plain := ask(t, append(append([]string{}, owners...), "--bundle", path)...); plain.stdout != got.stdout {
		t.Errorf("--explain changed the bundle's answers")
	}
}

// With --explain, each population's fix follows what is asked of it: the
// edit in one sentence, what a proven one takes out, the headline the
// policy opens on after it and the digest of the policy it leaves, which is
// the digest of the policy with the principal removed by hand, or of the
// policy that lets no one in where removing it would leave no statement;
// or why no fix can be proven yet.
func TestExplainSaysTheFix(t *testing.T) {
	const policy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"},{"Sid":"Partner","Effect":"Allow","Principal":{"AWS":["arn:aws:iam::111122223333:root","444455556666"]},"Action":"sts:AssumeRole"}]}`
	const twice = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["111122223333","arn:aws:iam::111122223333:root"]},"Action":"sts:AssumeRole"}]}`
	const noOneIn = "{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [\n    {\n      \"Sid\": \"DenyEveryone\",\n      \"Effect\": \"Deny\",\n      \"Principal\": {\"AWS\": \"*\"},\n      \"Action\": \"sts:AssumeRole\"\n    }\n  ]\n}"
	edited := strings.Replace(policy, `"arn:aws:iam::111122223333:root",`, "", 1)
	sum, replaced := sha256.Sum256([]byte(edited)), sha256.Sum256([]byte(noOneIn))
	dir := t.TempDir()
	path, only, named := filepath.Join(dir, "partner.json"), filepath.Join(dir, "only.json"), filepath.Join(dir, "twice.json")
	for file, text := range map[string]string{path: policy, only: oneAccount, named: twice} {
		if err := os.WriteFile(file, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		name  string
		args  []string
		lines []string
	}{
		{"a principal removed", []string{"--owner", "aws:444455556666", path}, []string{
			`    fix  In statement 2 ("Partner"), line 1, remove "arn:aws:iam::111122223333:root" from Principal.AWS.`,
			"         Grant 2 is taken out, and no grant left lets aws:111122223333 in by name.",
			"         after it: ec2.amazonaws.com can assume this role.",
			"         sha256 of the policy after it: " + hex.EncodeToString(sum[:]),
		}},
		{"the policy replaced", []string{only}, []string{
			`    fix  Replace the whole trust policy with one that lets no one in: statement 1 ("Partner"), line 1, is its only statement, the only principal it names is "arn:aws:iam::111122223333:root", and IAM refuses a trust policy with no statement.` +
				` This stops aws:111122223333 from getting in. If you still work with them, don't apply it.` +
				` Anyone already in keeps their access until their session ends, which can take hours. The role's "Revoke active sessions" ends those sessions now.` +
				` Deleting the role instead also removes what its permissions allow.`,
			"         Grant 1 is taken out, and no grant left lets anyone in.",
			"         after it: Nothing outside your company can assume this role.",
			"         sha256 of the policy after it: " + hex.EncodeToString(replaced[:]),
		}},
		{"no fix proven", []string{named}, []string{
			"    fix  No fix the engine can prove yet: grant 2 also lets aws:111122223333 in by name, so removing this principal does not shut it out.",
		}},
	} {
		got := ask(t, append([]string{"--explain"}, c.args...)...)
		if got.code != 0 {
			t.Fatalf("%s: exit %d, %s", c.name, got.code, got.stderr)
		}
		if want := "\n" + strings.Join(c.lines, "\n") + "\n"; !strings.Contains(got.stderr, want) {
			t.Errorf("%s: --explain does not say the fix:\n%s\nwant the lines\n%s", c.name, got.stderr, want)
		}
	}
}

// With --explain, a role AWS made and manages for one of its services says,
// for its fix, that its trust policy is AWS's to write and nobody in the
// account can edit it, never a condition to add to it; the answer, on
// standard output and in --json, is the trust policy's own.
func TestExplainSaysAWSManagedRolesCannotBeEdited(t *testing.T) {
	path, owners := bundleCase(t, "01-aws-service-linked-roles")
	got := ask(t, append(append([]string{"--explain"}, owners...), "--bundle", path)...)
	if got.code != 0 {
		t.Fatalf("exit %d, %s", got.code, got.stderr)
	}
	examined := 0
	for _, service := range []string{"organizations.amazonaws.com", "support.amazonaws.com", "trustedadvisor.amazonaws.com"} {
		examined++
		line := "\n    fix  No fix the engine can prove yet: AWS manages this role's trust policy for " + service + ", and nobody in this account can edit it.\n"
		if !strings.Contains(got.stderr, line) {
			t.Errorf("the role AWS made for %s does not say %q", service, strings.TrimSpace(line))
		}
	}
	if strings.Contains(got.stderr, "aws:SourceAccount") || examined != 3 {
		t.Errorf("a role AWS manages is given a condition to add to its trust policy:\n%s", got.stderr)
	}
	if plain := ask(t, append(append([]string{}, owners...), "--bundle", path)...); plain.stdout != got.stdout {
		t.Errorf("--explain changed the bundle's answers")
	}
}

// With --explain, the reader's own account is never told how to shut
// itself out: no fix is printed for the population declared as yours,
// while the partner beside it keeps its own.
func TestExplainPrintsNoFixForWhatIsYours(t *testing.T) {
	path := "../../testdata/fixes/07-statement-holding-your-own-account/aws.json"
	got := ask(t, "--explain", "--owner", "aws:444455556666", path)
	if got.code != 0 {
		t.Fatalf("exit %d, %s", got.code, got.stderr)
	}
	_, yours, ok := strings.Cut(got.stderr, "\n    who  aws:444455556666, declared as yours, can assume this role.\n")
	if !ok {
		t.Fatalf("no population is declared as yours:\n%s", got.stderr)
	}
	if block, _, _ := strings.Cut(yours, "\n  grant "); strings.Contains(block, "    fix  ") {
		t.Errorf("your own account is given a fix:\n%s", block)
	}
	if !strings.Contains(got.stderr, "\n    fix  In statement 1 (\"PartnerAndUs\"), lines 4-9, remove \"arn:aws:iam::111122223333:root\" from Principal.AWS.\n") {
		t.Errorf("the partner beside your account is not given its fix:\n%s", got.stderr)
	}
}
