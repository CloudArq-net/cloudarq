package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/CloudArq-net/cloudarq/internal/report"
)

// The tests run the built command rather than calling into package main,
// because what is asserted here is the surface: the bytes on each stream,
// the exit code and what the environment can and cannot change about them.
// A test that called the functions directly would assert none of those.
var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cloudarq-cmd")
	if err != nil {
		panic(err)
	}
	binary = filepath.Join(dir, "cloudarq")
	build := exec.Command("go", "build", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		os.Stderr.Write(out)
		os.RemoveAll(dir)
		panic("build the command under test: " + err.Error())
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

const testdata = "../../testdata"

type result struct {
	stdout, stderr string
	code           int
}

// invocation is one run of the command: its arguments, what it reads on
// standard input and the environment it runs under.
type invocation struct {
	args  []string
	stdin string
	env   []string // nil inherits nothing but PATH and HOME
}

func (in invocation) run(t *testing.T) result {
	t.Helper()
	cmd := exec.Command(binary, in.args...)
	cmd.Stdin = strings.NewReader(in.stdin)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}, in.env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if exit, ok := err.(*exec.ExitError); ok {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatalf("run %v: %v", in.args, err)
	}
	return result{stdout.String(), stderr.String(), code}
}

// ask runs the flagship subcommand and gives back what it wrote.
func ask(t *testing.T, args ...string) result {
	t.Helper()
	return invocation{args: append([]string{"admits"}, args...)}.run(t)
}

// corpus is every AWS document under testdata, by path, plus the escape
// fixture, which is the only document that carries a terminal escape.
func corpus(t *testing.T) map[string][]byte {
	t.Helper()
	docs := map[string][]byte{}
	patterns := []string{
		filepath.Join(testdata, "policies", "*.json"),
		filepath.Join(testdata, "grants", "*", "aws.json"),
		filepath.Join("..", "..", "internal", "report", "testdata", "escapes.json"),
	}
	for _, pattern := range patterns {
		paths, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range paths {
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			docs[p] = raw
		}
	}
	if len(docs) < 20 {
		t.Fatalf("%d documents in the corpus; the tests would examine too little", len(docs))
	}
	return docs
}

func grantCase(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(testdata, "grants", name, "aws.json")
}

// The command prints the answer the package composes: the sentence
// word for word, the term table, the notes and a token the grant admits.
func TestAdmitsPrintsTheAnswer(t *testing.T) {
	path := grantCase(t, "01-one-repo-one-branch")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	a := report.AnswerOf(raw)
	got := ask(t, path)
	if got.code != 0 || got.stderr != "" {
		t.Fatalf("exit %d, stderr %q", got.code, got.stderr)
	}
	for _, want := range []string{
		a.Grants[0].Sentence,
		a.Grants[0].Caption,
		"CLAIM",
		"ADMITS",
		"IN WORDS · AS WRITTEN",
		a.Grants[0].WitnessHeading,
		a.Document.SHA256,
	} {
		if !strings.Contains(got.stdout, want) {
			t.Errorf("the output does not carry %q\n%s", want, got.stdout)
		}
	}
	for _, line := range strings.Split(a.Grants[0].Witness, "\n") {
		if !strings.Contains(got.stdout, line) {
			t.Errorf("the witness line %q is not printed", line)
		}
	}
}

// --json is the engine's bytes and one newline, for every document in the
// corpus. The JSON is a public API, and the differential that holds the
// WebAssembly build to the native one (web/engine/diff.mjs) is only
// meaningful while the two emit the same bytes.
func TestJSONIsTheEnginesBytes(t *testing.T) {
	for path, raw := range corpus(t) {
		got := ask(t, "--json", path)
		if got.stdout != string(report.Admits(raw))+"\n" {
			t.Errorf("%s: --json is not the engine's bytes and one newline", path)
		}
		var a report.Answer
		if err := json.Unmarshal([]byte(got.stdout), &a); err != nil {
			t.Errorf("%s: %v", path, err)
		} else if a.V != 1 {
			t.Errorf("%s: v = %d", path, a.V)
		}
	}
}

// Every sentence the text prints is the answer's own. A renderer that
// paraphrased for the terminal would pass every other test here. The text
// is given each sentence without the control characters a terminal acts
// on, and every other character verbatim, so that is the form looked for:
// a claim name carrying an escape reaches the witness caption of the
// fixture that carries escapes.
func TestTheTextIsTheAnswersWords(t *testing.T) {
	checked, stripped := 0, 0
	for path, raw := range corpus(t) {
		text := ask(t, path).stdout
		a := report.AnswerOf(raw)
		if a.Error != "" {
			continue
		}
		for _, note := range a.Document.Anomalies {
			if !strings.Contains(text, note.Message) {
				t.Errorf("%s: the document note %q is not printed", path, note.Message)
			}
			checked++
		}
		for _, g := range a.Grants {
			for _, want := range append([]string{g.Sentence, g.Caption, g.WitnessCaption}, messages(g.Notes)...) {
				if want == "" {
					continue
				}
				if printable(want) != want {
					stripped++
				}
				if !strings.Contains(text, printable(want)) {
					t.Errorf("%s grant %d: %q is not printed", path, g.Number, want)
				}
				checked++
			}
		}
	}
	if checked < 100 || stripped == 0 {
		t.Fatalf("%d sentences checked, %d of them carrying a control character; the corpus did not load", checked, stripped)
	}
	t.Logf("%d sentences of the answer found verbatim in the text, %d without their control characters", checked, stripped)
}

// printable is a sentence as the text prints it: without the control
// characters a terminal acts on, U+0000 to U+001F and U+007F to U+009F, the
// newline and the tab among them.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r >= 0x7f && r <= 0x9f {
			return -1
		}
		return r
	}, s)
}

func messages(notes []report.Note) []string {
	out := make([]string, len(notes))
	for i, n := range notes {
		out[i] = n.Message
	}
	return out
}

// The exit codes. A wide-open policy exits 0: the code says whether the
// question was answered and never what the answer was, because a non-zero
// exit on a wide-open policy would be the command ranking what it read.
func TestExitCodes(t *testing.T) {
	wide := ask(t, grantCase(t, "06-unconstrained"))
	if wide.code != 0 {
		t.Errorf("a policy that admits everyone exited %d; the exit code rated the answer", wide.code)
	}
	if !strings.Contains(wide.stdout, "every identity") {
		t.Errorf("the wide-open policy's sentence is missing:\n%s", wide.stdout)
	}

	notADocument := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(notADocument, []byte("this is not a trust policy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unread := ask(t, notADocument)
	sentence := report.AnswerOf([]byte("this is not a trust policy\n")).Error
	if unread.code != 1 {
		t.Errorf("a document that is not a trust policy exited %d, want 1", unread.code)
	}
	if strings.TrimSpace(unread.stderr) != sentence {
		t.Errorf("stderr = %q, want the engine's sentence %q", unread.stderr, sentence)
	}
	if !strings.Contains(unread.stdout, sentence) {
		t.Errorf("the complete answer must stay on stdout on exit 1; stdout = %q", unread.stdout)
	}
	// the refusal says which documents this command reads, on both
	// surfaces: the engine's sentence says what went wrong with the bytes
	// and not which dialects have a reader
	const reads = "The document was not read as an AWS trust policy, and this command reads no other dialect."
	if !strings.Contains(unread.stdout, reads) {
		t.Errorf("the refusal does not say what this command reads:\n%s", unread.stdout)
	}
	if withToken := ask(t, "--token", `{"sub":"x"}`, notADocument); !strings.Contains(withToken.stdout, reads) || withToken.code != 1 {
		t.Errorf("with a token, the refusal is: exit %d\n%s", withToken.code, withToken.stdout)
	}
	unreadJSON := ask(t, "--json", notADocument)
	if unreadJSON.code != 1 || unreadJSON.stdout != string(report.Admits([]byte("this is not a trust policy\n")))+"\n" {
		t.Errorf("--json on an unreadable document: exit %d, stdout %q", unreadJSON.code, unreadJSON.stdout)
	}

	for _, args := range [][]string{{}, {"scan"}, {"admits"}, {"admits", "a.json", "b.json"}, {"admits", "--nonesuch", "a.json"}} {
		got := invocation{args: args}.run(t)
		if got.code != 2 {
			t.Errorf("%v exited %d, want 2", args, got.code)
		}
		if !strings.Contains(got.stderr, "usage: cloudarq admits") {
			t.Errorf("%v: no usage on stderr: %q", args, got.stderr)
		}
		if got.stdout != "" {
			t.Errorf("%v: wrote %q to stdout; usage goes to stderr", args, got.stdout)
		}
	}

	version := invocation{args: []string{"version"}}.run(t)
	if version.code != 0 || !strings.HasPrefix(version.stdout, "cloudarq ") {
		t.Errorf("version: exit %d, stdout %q", version.code, version.stdout)
	}
}

// Nothing about the environment changes the bytes but the colour the
// command was asked for.
func TestTheEnvironmentCannotChangeTheBytes(t *testing.T) {
	path := grantCase(t, "07-expressible-by-one-provider")
	plain := ask(t, path).stdout
	for _, env := range [][]string{
		{"LANG=tr_TR.UTF-8"},
		{"LC_ALL=C"},
		{"LANG=C", "LC_ALL=tr_TR.UTF-8", "TZ=Pacific/Kiritimati"},
		{"TERM=xterm-256color"},
		{"NO_COLOR=1"},
		{"NO_COLOR="},
		{"CLICOLOR_FORCE=1"},
	} {
		got := invocation{args: []string{"admits", path}, env: env}.run(t)
		if got.stdout != plain {
			t.Errorf("%v changed the output", env)
		}
	}
	if withFlag := ask(t, "--no-color", path).stdout; withFlag != plain {
		t.Error("--no-color changed the output of a command that was not colouring")
	}
	for _, b := range []byte(plain) {
		if b < 0x20 && b != '\n' {
			t.Fatalf("a control byte %#x reached the output", b)
		}
	}
}

// The bytes are read and not touched: the digest on the evidence line
// is the digest of the file, and the offsets index the file's own bytes.
func TestTheInputIsNotTouched(t *testing.T) {
	policy, err := os.ReadFile(grantCase(t, "01-one-repo-one-branch"))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"as written":           policy,
		"crlf":                 bytes.ReplaceAll(policy, []byte("\n"), []byte("\r\n")),
		"byte order mark":      append([]byte("\ufeff"), policy...),
		"no trailing newline":  bytes.TrimRight(policy, "\n"),
		"trailing blank lines": append(policy, '\n', '\n', ' '),
		"a byte that is not utf-8 in a Sid": bytes.Replace(policy,
			[]byte(`"Sid": "`), append([]byte(`"Sid": "`), 0xff), 1),
	}
	for name, raw := range cases {
		path := filepath.Join(t.TempDir(), "policy.json")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		got := ask(t, path)
		sum := sha256.Sum256(raw)
		digest := hex.EncodeToString(sum[:])
		a := report.AnswerOf(raw)
		if a.Error != "" {
			if got.code != 1 {
				t.Errorf("%s: exit %d on a document the engine refused", name, got.code)
			}
			continue
		}
		if !strings.Contains(got.stdout, "sha256 "+digest) {
			t.Errorf("%s: the document digest on the evidence line is not the digest of the file", name)
		}
		for _, s := range a.Document.Statements {
			if s.Offset+s.Length > len(raw) || !strings.Contains(got.stdout, "offset "+strconv.Itoa(s.Offset)) {
				t.Errorf("%s: statement[%d] at offset %d is not indexed into the file's own bytes", name, s.Index, s.Offset)
			}
			quoted := raw[s.Offset : s.Offset+s.Length]
			sum := sha256.Sum256(quoted)
			if hex.EncodeToString(sum[:]) != s.SHA256 {
				t.Errorf("%s: statement[%d]'s digest is not the digest of the bytes it points at", name, s.Index)
			}
		}
	}
}

// The bounds are the report's, and the sentence names the bound and
// the size that exceeded it.
func TestTheBoundsAreTheReports(t *testing.T) {
	head := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity"}],"Id":"`
	padded := func(n int) []byte {
		return []byte(head + strings.Repeat("a", n-len(head)-2) + `"}`)
	}
	write := func(raw []byte) string {
		path := filepath.Join(t.TempDir(), "policy.json")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if got := ask(t, write(padded(report.MaxDocumentBytes))); got.code != 0 {
		t.Errorf("a document at the bound exited %d: %s", got.code, got.stderr)
	}
	over := ask(t, write(padded(report.MaxDocumentBytes+1)))
	want := report.AnswerOf(padded(report.MaxDocumentBytes + 1)).Error
	if over.code != 1 || strings.TrimSpace(over.stderr) != want {
		t.Errorf("a document one byte over the bound: exit %d, stderr %q, want 1 and %q", over.code, over.stderr, want)
	}
	if !strings.Contains(want, strconv.Itoa(report.MaxDocumentBytes)) {
		t.Errorf("the refusal does not name the bound: %q", want)
	}
	// The bytes the command hands over are the file's, whitespace and all,
	// so a file past the bound is past it however it ends.
	whitespace := append(padded(report.MaxDocumentBytes), " \n\n\n"...)
	if past := ask(t, write(whitespace)); past.code != 1 || strings.TrimSpace(past.stderr) != want {
		t.Errorf("a document four whitespace bytes past the bound: exit %d, stderr %q, want 1 and %q", past.code, past.stderr, want)
	}

	policy := write(padded(report.MaxDocumentBytes))
	token := func(n int) string { return `{"sub":"` + strings.Repeat("b", n-10) + `"}` }
	if got := ask(t, "--token", token(report.MaxTokenBytes), policy); got.code != 0 {
		t.Errorf("a token at the bound exited %d: %s", got.code, got.stderr)
	}
	overToken := ask(t, "--token", token(report.MaxTokenBytes+1), policy)
	if overToken.code != 1 || !strings.Contains(overToken.stderr, strconv.Itoa(report.MaxTokenBytes)) {
		t.Errorf("a token one byte over the bound: exit %d, stderr %q", overToken.code, overToken.stderr)
	}
}

// long is standard input of zeros, far past the bound, counting what was
// read of it. It ends, at eight times the bound, only so that a command
// that reads to the end fails this test rather than the machine.
type long struct{ read int }

func (l *long) Read(p []byte) (int, error) {
	n := min(len(p), 8*report.MaxDocumentBytes-l.read)
	if n == 0 {
		return 0, io.EOF
	}
	clear(p[:n])
	l.read += n
	return n, nil
}

// A document is read one byte past the bound and no further, so input of
// any length costs what the bound costs: from standard input, and from a
// path that never reaches its end. The answer names the bound, as it does for a
// file one byte past it.
func TestInputPastTheBoundIsNotReadToItsEnd(t *testing.T) {
	in := &long{}
	var stdout, stderr bytes.Buffer
	code := run([]string{"admits", "-", "--json"}, in, &stdout, &stderr, false)
	want := report.AnswerOf(make([]byte, report.MaxDocumentBytes+1)).Error
	if code != 1 || strings.TrimSpace(stderr.String()) != want || !strings.Contains(stdout.String(), `"error"`) {
		t.Errorf("long standard input: exit %d, stderr %q, stdout %.80q; want 1, %q and the answer", code, stderr.String(), stdout.String(), want)
	}
	if in.read > report.MaxDocumentBytes+1 {
		t.Errorf("long standard input: %d bytes were read, past the %d the bound needs", in.read, report.MaxDocumentBytes+1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "admits", "/dev/zero")
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	err := cmd.Run()
	exit, ok := err.(*exec.ExitError)
	if ctx.Err() != nil || !ok || exit.ExitCode() != 1 || strings.TrimSpace(errOut.String()) != want {
		t.Errorf("admits /dev/zero: %v, stderr %q; want exit 1 and %q within 20 seconds", err, errOut.String(), want)
	}
}

// "-" reads standard input, and the answer is the same as for the
// same bytes in a file.
func TestStandardInput(t *testing.T) {
	path := grantCase(t, "03-whole-organisation")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fromFile := ask(t, path)
	fromStdin := invocation{args: []string{"admits", "-"}, stdin: string(raw)}.run(t)
	if fromStdin.stdout != fromFile.stdout || fromStdin.code != 0 {
		t.Errorf("stdin and the file disagree: exit %d\n%s", fromStdin.code, fromStdin.stdout)
	}
	jsonFromStdin := invocation{args: []string{"admits", "--json", "-"}, stdin: string(raw)}.run(t)
	if jsonFromStdin.stdout != string(report.Admits(raw))+"\n" {
		t.Error("--json from stdin is not the engine's bytes")
	}
	missing := ask(t, filepath.Join(t.TempDir(), "nothing.json"))
	if missing.code != 1 || !strings.Contains(missing.stderr, "nothing.json") {
		t.Errorf("a file that does not exist: exit %d, stderr %q", missing.code, missing.stderr)
	}
}

// The token surface: the explanation is the report's, grant by grant.
func TestTokenExplainsGrantByGrant(t *testing.T) {
	path := grantCase(t, "03-whole-organisation")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	token := `{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:ref:refs/heads/main","repository_owner_id":"123456"}`
	x := report.ExplanationOf(raw, []byte(token))
	got := ask(t, "--token", token, path)
	if got.code != 0 {
		t.Fatalf("exit %d: %s", got.code, got.stderr)
	}
	for _, want := range []string{x.Sentence, x.Grants[0].Sentence} {
		if !strings.Contains(got.stdout, want) {
			t.Errorf("the explanation does not carry %q\n%s", want, got.stdout)
		}
	}
	asJSON := ask(t, "--json", "--token", token, path)
	if asJSON.stdout != string(report.Explain(raw, []byte(token)))+"\n" {
		t.Error("--json --token is not the engine's explanation bytes")
	}
	badToken := ask(t, "--token", "not a token", path)
	if badToken.code != 1 || !strings.Contains(badToken.stderr, "neither a decoded payload") {
		t.Errorf("a token that cannot be read: exit %d, stderr %q", badToken.code, badToken.stderr)
	}
	// The document here was read. A refusal that said otherwise would send
	// a reader to check the wrong file, and it would be untrue.
	if strings.Contains(badToken.stdout, "The document was not read") {
		t.Errorf("a token that cannot be read says the document was not read:\n%s", badToken.stdout)
	}
}

// TestAKeyIsReadFromTheClaimAWSReadsItFrom: a condition key does not always
// read the claim of its own name. AWS's Default tab, which GitHub's and
// Google's tokens are read by: "oaud aud" and "aud azp If no value is set
// for azp, the aud condition key maps to the aud claim." So --token tests
// oaud against the token's aud, and aud against its azp, or its aud when it
// sets no azp; a token that sets azp to the empty string or to null leaves
// open which of the two AWS reads, and is not proven admitted. The witness
// carries the claim AWS reads, and the command's own explanation admits it.
func TestAKeyIsReadFromTheClaimAWSReadsItFrom(t *testing.T) {
	const (
		github = `"iss":"https://token.actions.githubusercontent.com"`
		google = `"iss":"https://accounts.google.com"`
		entra  = `"iss":"https://login.microsoftonline.com/ffffffff-eeee-dddd-cccc-bbbbbbbbbbb0/v2.0"`
		client = "123456789012-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com"
		app    = "11111111-2222-3333-4444-555555555555"
		main   = `"sub":"repo:acme/infra:ref:refs/heads/main"`
	)
	tokens := []struct {
		name, token, result string
	}{
		{"58-oaud-reads-aud", `{` + github + `,"aud":"sts.amazonaws.com","sub":"repo:acme/app:ref:refs/heads/main"}`, "admitted"},
		{"58-oaud-reads-aud", `{` + github + `,"aud":"api://another","oaud":"sts.amazonaws.com","sub":"repo:acme/app:ref:refs/heads/main"}`, "not admitted"},
		{"01-branch-pin-and-owner-prefix", `{` + github + `,"aud":"sts.amazonaws.com",` + main + `}`, "admitted"},
		{"01-branch-pin-and-owner-prefix", `{` + github + `,"aud":"sts.amazonaws.com","azp":"another-party",` + main + `}`, "not admitted"},
		{"01-branch-pin-and-owner-prefix", `{` + github + `,"aud":"api://another","azp":"sts.amazonaws.com",` + main + `}`, "admitted"},
		{"01-branch-pin-and-owner-prefix", `{` + github + `,"aud":"sts.amazonaws.com","azp":"",` + main + `}`, "not proven"},
		{"01-branch-pin-and-owner-prefix", `{` + github + `,"aud":"sts.amazonaws.com","azp":null,` + main + `}`, "not proven"},
		{"01-branch-pin-and-owner-prefix", `{` + github + `,"aud":"api://another","azp":"",` + main + `}`, "not admitted"},
		{"13-google", `{` + google + `,"aud":"` + client + `","sub":"110169484474386276334"}`, "admitted"},
		{"13-google", `{` + google + `,"aud":"api://another","azp":"` + client + `","sub":"110169484474386276334"}`, "admitted"},
		{"13-google", `{` + google + `,"aud":"` + client + `","azp":"another-client","sub":"110169484474386276334"}`, "not admitted"},
		{"59-entra-audience-reads-azp", `{` + entra + `,"aud":"api://another","azp":"` + app + `"}`, "admitted"},
		{"59-entra-audience-reads-azp", `{` + entra + `,"aud":"` + app + `","azp":"another-client"}`, "not admitted"},
	}
	for _, c := range tokens {
		path, _ := ringsCase(t, c.name)
		got := ask(t, "--json", "--token", c.token, path)
		var x report.Explanation
		if err := json.Unmarshal([]byte(got.stdout), &x); got.code != 0 || err != nil {
			t.Fatalf("%s: exit %d, %v: %s", c.name, got.code, err, got.stderr)
		}
		if x.Result != c.result {
			t.Errorf("%s, token %s: %q, want %q: %s", c.name, c.token, x.Result, c.result, x.Sentence)
		}
	}
	witnesses := []struct {
		name, carries, lacks string
	}{
		{"58-oaud-reads-aud", `"aud": "sts.amazonaws.com"`, `"oaud"`},
		{"01-branch-pin-and-owner-prefix", `"aud": "sts.amazonaws.com"`, `"azp"`},
		{"13-google", `"aud": "` + client + `"`, `"azp"`},
		{"59-entra-audience-reads-azp", `"aud": "` + app + `"`, `"azp"`},
	}
	for _, c := range witnesses {
		path, _ := ringsCase(t, c.name)
		got := ask(t, "--json", path)
		var a report.Answer
		if err := json.Unmarshal([]byte(got.stdout), &a); got.code != 0 || err != nil {
			t.Fatalf("%s: exit %d, %v: %s", c.name, got.code, err, got.stderr)
		}
		g := a.Grants[0]
		if !strings.Contains(g.Witness, c.carries) || strings.Contains(g.Witness, c.lacks) {
			t.Errorf("%s: the witness carries %s and no %s claim, it is:\n%s", c.name, c.carries, c.lacks, g.Witness)
			continue
		}
		if c.lacks == `"azp"` && !strings.Contains(g.WitnessCaption, "azp") {
			t.Errorf("%s: the witness sets no azp, and its caption does not say why: %s", c.name, g.WitnessCaption)
		}
		explained := ask(t, "--json", "--token", g.Witness, path)
		var x report.Explanation
		if err := json.Unmarshal([]byte(explained.stdout), &x); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if o := x.Grants[0]; !o.Admitted || !o.Witness || x.Result != "admitted" {
			t.Errorf("%s: the command does not admit its own witness: admitted=%v witness=%v result %q", c.name, o.Admitted, o.Witness, x.Result)
		}
	}
}

// --explain says what the command will read and call before it answers,
// and says it on standard error so that stdout stays the answer.
func TestExplainSaysWhatItWouldDo(t *testing.T) {
	path := grantCase(t, "03-whole-organisation")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := ask(t, "--explain", "--json", path)
	if got.code != 0 {
		t.Fatalf("exit %d: %s", got.code, got.stderr)
	}
	if got.stdout != string(report.Admits(raw))+"\n" {
		t.Error("--explain wrote to stdout; the answer must be the only thing there")
	}
	for _, want := range []string{path, "NO_COLOR", "no network request", "reads"} {
		if !strings.Contains(got.stderr, want) {
			t.Errorf("--explain does not say %q:\n%s", want, got.stderr)
		}
	}
	// every run is offline, so no flag asks for it: one that did would
	// promise a mode the command does not have
	if got := ask(t, "--offline", path); got.code != 2 || got.stdout != "" {
		t.Errorf("--offline: exit %d, stdout %q; want 2 and nothing, as for any flag the command does not have", got.code, got.stdout)
	}
}

// Colour is the command's one decision about the terminal. A test's stdout
// is a pipe, so the decision is exercised through run directly, with the
// answer it would have got from a terminal handed in: the alternative is a
// pseudo-terminal, which would test this machine's ioctls rather than the
// command.
func TestColourIsTheOneThingTheTerminalDecides(t *testing.T) {
	policy, err := os.ReadFile(grantCase(t, "06-unconstrained"))
	if err != nil {
		t.Fatal(err)
	}
	unevaluated, err := os.ReadFile(grantCase(t, "07-expressible-by-one-provider"))
	if err != nil {
		t.Fatal(err)
	}
	rendered := func(terminal bool, document []byte, args ...string) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if code := run(append(args, "-"), bytes.NewReader(document), &stdout, &stderr, terminal); code != 0 {
			t.Fatalf("exit %d: %s", code, stderr.String())
		}
		return stdout.String()
	}
	plain := rendered(false, policy, "admits")
	coloured := rendered(true, policy, "admits")
	if stripped := escapes.ReplaceAllString(coloured, ""); stripped != plain {
		t.Error("colour changed more than the marks")
	}
	// the answer's three marks and no fourth: what is known exactly,
	// what is admitted beyond any boundary the document names, and what was
	// not evaluated
	for mark, want := range map[string]bool{"[34m": true, "[31m": true, "[35m": false} {
		if strings.Contains(coloured, escape+mark) != want {
			t.Errorf("a policy that admits everyone: %q present = %v, want %v", mark, !want, want)
		}
	}
	if !strings.Contains(rendered(true, unevaluated, "admits"), escape+"[35m") {
		t.Error("a claim that was not evaluated earns no mark")
	}
	for _, sequence := range escapes.FindAllString(coloured+rendered(true, unevaluated, "admits"), -1) {
		switch sequence {
		case escape + "[34m", escape + "[31m", escape + "[35m", escape + "[0m":
		default:
			t.Errorf("a fourth colour: %q", sequence)
		}
	}
	if got := rendered(true, policy, "admits", "--no-color"); got != plain {
		t.Error("--no-color did not turn the marks off")
	}
	t.Setenv("NO_COLOR", "1")
	if got := rendered(true, policy, "admits"); got != plain {
		t.Error("NO_COLOR did not turn the marks off")
	}
	t.Setenv("NO_COLOR", "")
	if got := rendered(true, policy, "admits"); got != coloured {
		t.Error("an empty NO_COLOR turned the marks off; only a set variable does")
	}
}

// escape is the byte a terminal acts on, spelt rather than written, and
// escapes is every sequence that starts with it.
const escape = "\x1b"

var escapes = regexp.MustCompile(escape + `\[[0-9;]*m`)

// The goldens are the command's output as a reader sees it, one file per
// document, beside the rationale that says why that is the right answer.
// They are what a change to the words in internal/report has to walk past:
// every other test here compares the command against the package, so the
// two would move together and agree.
var update = flag.Bool("update", false, "write the golden files from this run, then read the rationale beside each and say why the new answer is right")

var goldens = map[string]string{
	"01-one-repo-one-branch":         "",
	"02-one-repo-any-branch":         "",
	"03-whole-organisation":          "",
	"04-immutable-subject":           "",
	"05-repository-id":               "",
	"06-unconstrained":               "",
	"07-expressible-by-one-provider": "",
	"escapes":                        filepath.Join("..", "..", "internal", "report", "testdata", "escapes.json"),
}

func TestGoldenOutput(t *testing.T) {
	for name, path := range goldens {
		if path == "" {
			path = grantCase(t, name)
		}
		for _, form := range []struct {
			extension string
			args      []string
		}{
			{".txt", []string{path}},
			{".json", []string{"--json", path}},
		} {
			golden := filepath.Join("testdata", name+form.extension)
			got := ask(t, form.args...)
			if got.code != 0 {
				t.Fatalf("%s: exit %d, %s", name, got.code, got.stderr)
			}
			if *update {
				if err := os.WriteFile(golden, []byte(got.stdout), 0o600); err != nil {
					t.Fatal(err)
				}
				continue
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if got.stdout != string(want) {
				t.Errorf("%s: the output is not the golden file\n--- got ---\n%s\n--- want ---\n%s", golden, got.stdout, want)
			}
		}
		// A golden with no rationale is folklore: the first time it
		// disagrees with reality, the file is what gets believed.
		if _, err := os.Stat(filepath.Join("testdata", name+".rationale.md")); err != nil {
			t.Errorf("%s has no rationale beside it: %v", name, err)
		}
	}
	if *update {
		t.Log("golden files written; read each rationale and say why the new answer is right")
	}
}

// A Sid and a claim's value are the user's bytes, and --json is what
// puts them on a terminal. The encoder writes the schema encoding/json
// writes, which escapes the C0 range and leaves the C1 range as it found
// it; U+009B is the 8-bit CONTROL SEQUENCE INTRODUCER, which a terminal
// acts on exactly as it acts on ESC [. The text rendering drops those
// characters and the JSON cannot — it carries the document's values — so
// what the command writes escapes them instead.
func TestJSONPutsNoControlCharacterOnTheTerminal(t *testing.T) {
	raw := []byte("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"C1\u009b31mRed\",\"Effect\":\"Allow\",\"Principal\":{\"Federated\":\"token.actions.githubusercontent.com\"},\"Action\":\"sts:AssumeRoleWithWebIdentity\",\"Condition\":{\"StringEquals\":{\"token.actions.githubusercontent.com:aud\":\"sts\u009b31m.amazonaws.com\",\"token.actions.githubusercontent.com:sub\":\"repo:acme/infra\x7f:ref:refs/heads/main\"}}}]}")
	path := filepath.Join(t.TempDir(), "c1.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if n := controlRunes(string(raw)); n != 3 {
		t.Fatalf("the document carries %d control characters, want 3; the test would prove nothing", n)
	}
	token := "{\"iss\":\"https://token.actions.githubusercontent.com\",\"aud\":\"sts\u009b31m.amazonaws.com\"}"
	for _, args := range [][]string{{path}, {"--json", path}, {"--token", token, path}, {"--json", "--token", token, path}} {
		got := ask(t, args...)
		if got.code != 0 {
			t.Fatalf("%v: exit %d, %s", args, got.code, got.stderr)
		}
		if n := controlRunes(got.stdout); n != 0 {
			t.Errorf("%v: %d control characters reached standard output:\n%s", args, n, quoteControls(got.stdout))
		}
	}
	// the escaping is of the writing, not of the answer: the same values,
	// in the same schema, for whoever parses what the pipeline stored
	var got, want report.Answer
	if err := json.Unmarshal([]byte(ask(t, "--json", path).stdout), &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(report.Admits(raw), &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Error("the answer written to the terminal is not the answer the engine composed")
	}
	if !strings.Contains(got.Document.Statements[0].Sid, "\u009b") {
		t.Errorf("the Sid was changed on its way out: %q", got.Document.Statements[0].Sid)
	}
}

// controlRunes counts the characters a terminal acts on: C0 and C1, the
// newline excepted. The rule is spelt out here rather than borrowed from
// the report, so that a change there cannot make this test agree with it.
func controlRunes(s string) int {
	n := 0
	for _, r := range s {
		if r != '\n' && (r < 0x20 || (r >= 0x7f && r <= 0x9f)) {
			n++
		}
	}
	return n
}

// quoteControls spells the characters a terminal would act on, so that a
// failure above can be read in the terminal it is printed to.
func quoteControls(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r != '\n' && (r < 0x20 || (r >= 0x7f && r <= 0x9f)) {
			b.WriteString(strconv.QuoteRune(r))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// The exit codes are a contract the command prints, and a script is
// written against the sentence it prints. Exit 1 covers three conditions,
// and the answer reaches standard output for two of them: the engine is
// total over the bytes it is given, and a file that never opened gave it
// none.
func TestTheUsageSaysWhatExitOneLeavesOnStandardOutput(t *testing.T) {
	for name, path := range map[string]string{
		"a file that does not exist": filepath.Join(t.TempDir(), "nothing.json"),
		"a directory":                t.TempDir(),
	} {
		got := ask(t, path)
		if got.code != 1 || got.stdout != "" || got.stderr == "" {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", name, got.code, got.stdout, got.stderr)
		}
	}
	notADocument := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(notADocument, []byte("this is not a trust policy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ask(t, notADocument); got.code != 1 || got.stdout == "" {
		t.Errorf("a document the engine refused: exit %d, stdout %q", got.code, got.stdout)
	}
	// the printed contract must name the condition that leaves standard
	// output empty; a script that parses stdout on exit 1 is written
	// against this paragraph and gets nothing to parse
	printed := invocation{args: nil}.run(t).stderr
	if !strings.Contains(printed, "could not be opened") {
		t.Errorf("the exit codes do not name the input that never reached the engine:\n%s", printed)
	}
}

// TestADocumentAWSRefusesIsRefusedNamingTheCharacter: a policy document may
// hold only tab, line feed, carriage return and U+0020 to U+00FF, and a
// ligature written as itself is none of them, so AWS refuses the document.
// The command refuses it as it refuses any document it cannot read: exit 1,
// the reason on standard error, and an answer on standard output that says
// the same and places no grant, rather than reading a policy that cannot
// exist as admitting anyone or no one.
func TestADocumentAWSRefusesIsRefusedNamingTheCharacter(t *testing.T) {
	document := `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "` + "\ufb05" + `s:AssumeRole"}]}`
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	reason := "parse trust policy: U+FB05 at byte " + strconv.Itoa(strings.Index(document, "\ufb05")) + " is a character AWS refuses in a policy document, which may hold only tab, line feed, carriage return and U+0020 to U+00FF"
	for _, args := range [][]string{{path}, {"--json", path}} {
		got := ask(t, args...)
		if got.code != 1 || strings.TrimSpace(got.stderr) != reason || !strings.Contains(got.stdout, reason) || strings.Contains(got.stdout, "nobody") {
			t.Errorf("%v: exit %d\nstdout %s\nstderr %s", args, got.code, got.stdout, got.stderr)
		}
	}
	if a := report.AnswerOf([]byte(document)); a.Error != reason || len(a.Grants) != 0 || a.Document != nil {
		t.Errorf("the answer: %+v", a)
	}
}

// Standard output is the report's rendering and nothing else. A sentence
// the command composes for itself passes every rule above even when the
// package still composes it too — the package's own words are all still
// there, in order, so a test that looks for them finds them — and the
// reader gets the refusal twice. The whole rendering is compared, and the
// count of the one sentence a second copy would duplicate is named as
// well, so that a failure says which of the two went wrong.
func TestTheRefusalIsTheReportsAndIsPrintedOnce(t *testing.T) {
	const reads = "The document was not read as an AWS trust policy, and this command reads no other dialect."
	path := filepath.Join(t.TempDir(), "notes.txt")
	raw := []byte("this is not a trust policy\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	const token = `{"sub":"repo:acme/infra:ref:refs/heads/main"}`
	for name, in := range map[string]struct {
		args []string
		want string
	}{
		"a document the engine could not read": {[]string{path}, report.AnswerOf(raw).Text(report.Options{})},
		"the same, with a token":               {[]string{"--token", token, path}, report.ExplanationOf(raw, []byte(token)).Text(report.Options{})},
	} {
		got := ask(t, in.args...)
		if n := strings.Count(got.stdout, reads); n != 1 {
			t.Errorf("%s: the sentence saying which dialect is read is printed %d times:\n%s", name, n, got.stdout)
		}
		if got.stdout != in.want {
			t.Errorf("%s: standard output is not the report's rendering.\nwrote: %q\nreport: %q", name, got.stdout, in.want)
		}
	}
}

// A mistyped flag is one mistake, and the usage block is twenty-four
// lines: printed twice it reads as two failures and buries the line that
// says which flag was wrong.
func TestTheUsageIsPrintedOnce(t *testing.T) {
	for _, args := range [][]string{{"admits", "--nonesuch", "a.json"}, {"admits", "-h"}, {"admits"}, {}, {"scan"}, {"admits", "a.json", "b.json"}} {
		got := invocation{args: args}.run(t)
		if n := strings.Count(got.stderr, "usage: cloudarq admits"); n != 1 {
			t.Errorf("%v: the usage block is printed %d times", args, n)
		}
		if got.stdout != "" {
			t.Errorf("%v: wrote %q to stdout", args, got.stdout)
		}
	}
}
