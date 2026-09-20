package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

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

// R5 · the command prints the answer the package composes: the sentence
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

// R6 · --json is the engine's bytes and one newline, for every document in
// the corpus. The JSON is a public API and the explorer's differential is
// only meaningful while the two surfaces emit the same bytes.
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

// R7 · every sentence the text prints is the answer's own. A renderer that
// paraphrased for the terminal would pass every other test here.
func TestTheTextIsTheAnswersWords(t *testing.T) {
	checked := 0
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
				if !strings.Contains(text, want) {
					t.Errorf("%s grant %d: %q is not printed", path, g.Number, want)
				}
				checked++
			}
		}
	}
	if checked < 100 {
		t.Fatalf("%d sentences checked; the corpus did not load", checked)
	}
	t.Logf("%d sentences of the answer found verbatim in the text", checked)
}

func messages(notes []report.Note) []string {
	out := make([]string, len(notes))
	for i, n := range notes {
		out[i] = n.Message
	}
	return out
}

// R8 · the exit codes. A wide-open policy exits 0: the code says whether
// the question was answered and never what the answer was
// (product/CONSTITUTION.md section 3, prohibition 13).
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
	const reads = "The document was not read as an AWS trust policy, and this command reads no other dialect yet."
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

// R10 · nothing about the environment changes the bytes but the colour the
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

// R11 · the bytes are read and not touched: the digest on the evidence line
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

// R12 · the bounds are the report's, and the sentence names the bound and
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
	if !strings.Contains(want, strconv.Itoa(report.MaxDocumentBytes)) || !strings.Contains(want, strconv.Itoa(report.MaxDocumentBytes+1)) {
		t.Errorf("the refusal names neither the bound nor the size: %q", want)
	}
	// The bytes the command hands over are the file's, whitespace and all,
	// so a file past the bound is past it however it ends. The size the
	// sentence names is the size wc prints.
	whitespace := append(padded(report.MaxDocumentBytes), " \n\n\n"...)
	past := ask(t, write(whitespace))
	wantPast := report.AnswerOf(whitespace).Error
	if past.code != 1 || strings.TrimSpace(past.stderr) != wantPast {
		t.Errorf("a document four whitespace bytes past the bound: exit %d, stderr %q, want 1 and %q", past.code, past.stderr, wantPast)
	}
	if !strings.Contains(wantPast, strconv.Itoa(report.MaxDocumentBytes+4)) {
		t.Errorf("the refusal does not name the size of the file: %q", wantPast)
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

// R13 · "-" reads standard input, and the answer is the same as for the
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
	if !strings.Contains(ask(t, "--offline", path).stdout, "aws trust policy") {
		t.Error("--offline is accepted and is the only mode")
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
	// the three marks of the explorer and no fourth: what is known exactly,
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

// A Sid and a claim's value are the customer's bytes, and --json is what
// puts them on a terminal. The encoder writes the schema encoding/json
// writes, which escapes the C0 range and leaves the C1 range as it found
// it; U+009B is the 8-bit CONTROL SEQUENCE INTRODUCER, which a terminal
// acts on exactly as it acts on ESC [. The text rendering drops those
// characters and the JSON cannot — it carries the document's values — so
// what the command writes escapes them instead.
func TestJSONPutsNoControlCharacterOnTheTerminal(t *testing.T) {
	raw := []byte("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"C131mRed\",\"Effect\":\"Allow\",\"Principal\":{\"Federated\":\"token.actions.githubusercontent.com\"},\"Action\":\"sts:AssumeRoleWithWebIdentity\",\"Condition\":{\"StringEquals\":{\"token.actions.githubusercontent.com:aud\":\"sts31m.amazonaws.com\",\"token.actions.githubusercontent.com:sub\":\"repo:acme/infra:ref:refs/heads/main\"}}}]}")
	path := filepath.Join(t.TempDir(), "c1.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if n := controlRunes(string(raw)); n != 3 {
		t.Fatalf("the document carries %d control characters, want 3; the test would prove nothing", n)
	}
	token := "{\"iss\":\"https://token.actions.githubusercontent.com\",\"aud\":\"sts31m.amazonaws.com\"}"
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
	if !strings.Contains(got.Document.Statements[0].Sid, "") {
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

// Standard output is the report's rendering and nothing else. A sentence
// the command composes for itself passes every rule above even when the
// package still composes it too — the package's own words are all still
// there, in order, so a test that looks for them finds them — and the
// reader gets the refusal twice. The whole rendering is compared, and the
// count of the one sentence a second copy would duplicate is named as
// well, so that a failure says which of the two went wrong.
func TestTheRefusalIsTheReportsAndIsPrintedOnce(t *testing.T) {
	const reads = "The document was not read as an AWS trust policy, and this command reads no other dialect yet."
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
