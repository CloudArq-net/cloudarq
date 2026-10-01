package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/CloudArq-net/cloudarq/internal/report"
)

const ringsCases = "../../testdata/rings"

// ringsCase is one case of testdata/rings, and the flags that declare its
// owners, one --owner for each line of its owners.txt.
func ringsCase(t *testing.T, name string) (path string, flags []string) {
	t.Helper()
	path = filepath.Join(ringsCases, name, "aws.json")
	owners, err := os.ReadFile(filepath.Join(ringsCases, name, "owners.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(owners), "\n"), "\n") {
		if line != "" {
			flags = append(flags, "--owner", line)
		}
	}
	return path, flags
}

func ringsCaseNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(ringsCases)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	if len(names) < 40 {
		t.Fatalf("%d rings cases; the goldens would cover too little", len(names))
	}
	return names
}

// TestRingsGoldens runs every case of testdata/rings end to end, a golden
// per ring and per trap: the command's text and its JSON, with the case's
// owners declared through --owner, beside the case's rationale, which says
// why each grant lands where it does and quotes the sentence it rests on.
// The default document runs as case 01, with no owner, and as case 32,
// with github:acme declared.
func TestRingsGoldens(t *testing.T) {
	declaring := 0
	for _, name := range ringsCaseNames(t) {
		path, owners := ringsCase(t, name)
		if len(owners) > 0 {
			declaring++
		}
		if _, err := os.Stat(filepath.Join(ringsCases, name, "rationale.md")); err != nil {
			t.Errorf("%s has no rationale: %v", name, err)
		}
		for _, form := range []struct {
			extension string
			args      []string
		}{
			{".txt", append(append([]string{}, owners...), path)},
			{".json", append(append([]string{"--json"}, owners...), path)},
		} {
			golden := filepath.Join("testdata", "rings", name+form.extension)
			got := ask(t, form.args...)
			if got.code != 0 || got.stderr != "" {
				t.Fatalf("%s: exit %d, %s", name, got.code, got.stderr)
			}
			if *update {
				if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
					t.Fatal(err)
				}
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
	}
	if declaring == 0 {
		t.Fatal("no rings case declares an owner; --owner went unexamined")
	}
}

// The answers as they stood before the rings, recorded when the command's
// goldens were first written, and pinned here by digest: a
// before-rings file rewritten to agree with a later answer fails here
// rather than passing the comparison below.
var beforeRings = map[string]string{
	"01-one-repo-one-branch":         "35111ddf98f60cd6e5d6ec74cd1d8e7d04aad451c6c421871f559b358d7099e7",
	"02-one-repo-any-branch":         "84b4aa453b15c0c67152fdba18d429f815c9d5703f0e65f2386d6e51164cc908",
	"03-whole-organisation":          "5ef4eb99f86649b49f326059fc1e05ab01476342a3d9e2b2a4a3651baf22329c",
	"04-immutable-subject":           "60c405b22c4b611d1a6b4a505d60b5cba427e678670ee6637ee9f2078dd2f01d",
	"05-repository-id":               "41cfb47dfd6d1a655104775086abde9480f57db58498608dbed72efaa14147c8",
	"06-unconstrained":               "ab22c7f45b3aed685ea003487cc609c5af7fa3696ee84f0d075a54871a0f95f9",
	"07-expressible-by-one-provider": "2543f068ff4b810df1de47c75b989cda549b09f0677e74f0e9dcb54a0604dfab",
	"escapes":                        "f4ed98e6f7649bd0298f22e712cc2bf3ca725f801c301aa2c5e2f5e5c745b971",
}

// ringsField are the members the rings added to the answer, and nothing
// else: at the top, the headline, the rings, the lines beside them, the
// grants in no ring, the declarations and the bounds; on a grant, its
// placement, the placement's state and its populations.
func ringsField(path string) bool {
	switch path {
	case ".headline", ".rings", ".beside", ".refused", ".nobody", ".declarations", ".bounds",
		".grants[].placement", ".grants[].placementState", ".grants[].populations":
		return true
	}
	return false
}

// TestTheAnswerOnlyGrew is what "v stays 1" means: every golden answer with
// the rings' fields taken out is the answer the same document had before
// the rings, byte for byte. A field renamed, removed, moved or changed in
// meaning shows here; one added does not.
func TestTheAnswerOnlyGrew(t *testing.T) {
	if len(beforeRings) != len(goldens) {
		t.Fatalf("%d answers from before the rings for %d goldens", len(beforeRings), len(goldens))
	}
	stripped, reread := 0, 0
	for name, digest := range beforeRings {
		before, err := os.ReadFile(filepath.Join("testdata", "before-rings", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(before); hex.EncodeToString(sum[:]) != digest {
			t.Errorf("%s: the answer from before the rings was rewritten; its digest is %x", name, sum)
			continue
		}
		now, err := os.ReadFile(filepath.Join("testdata", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		// each golden is the command's output, the engine's bytes and the
		// one newline --json writes after them
		now, nowEnds := bytes.CutSuffix(now, []byte("\n"))
		before, beforeEnds := bytes.CutSuffix(before, []byte("\n"))
		if !nowEnds || !beforeEnds {
			t.Fatalf("%s: a golden does not end in the newline --json writes", name)
		}
		without, removed, err := withoutMembers(now, ringsField)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if removed == 0 {
			t.Errorf("%s: the golden carries none of the rings' fields; it was not re-recorded", name)
		}
		path := goldens[name]
		if path == "" {
			path = grantCase(t, name)
		}
		why, again := answerReadAgain(path)
		if err := grewOnly(why, again, without, before); err != nil {
			t.Errorf("%s: without the rings' fields the answer %v:\n now    %s\n before %s", name, err, without, before)
		}
		if again {
			reread++
		}
		stripped += removed
	}
	t.Logf("%d answers equal their answers from before the rings, %d read again lost no member, %d members of the rings' taken out", len(beforeRings)-reread, reread, stripped)
}

// The explanations as they stood before the rings, written by the command
// as it was built just before the rings were added: one line for each
// document of the goldens and of testdata/policies, in that order, and for
// each of these tokens, in this order. The file is pinned by digest, as
// the answers are.
const explanationsBeforeRings = "1d45a960dc839c5331ea6e0b4abe4238e02d746955307908ba47400b0bff11f0"

var beforeRingsTokens = []string{
	`{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:ref:refs/heads/main","repository_owner_id":"123456"}`,
	`{"iss":"https://gitlab.com","aud":"sts.amazonaws.com","sub":"project_path:acme/infra:ref_type:branch:ref:main"}`,
	// a whole token, header, payload and signature, whose payload names no
	// issuer and a repository no grant admits
	"eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJzdHMuYW1hem9uYXdzLmNvbSIsInN1YiI6InJlcG86b3RoZXIveDpyZWY6cmVmcy9oZWFkcy9kZXYifQ.c2ln",
}

// explanationField are the members the rings added to the explanation:
// the policy's result, the declarations and the bounds, and on each grant's
// outcome its placement and the placement's state.
func explanationField(path string) bool {
	switch path {
	case ".result", ".declarations", ".bounds", ".grants[].placement", ".grants[].placementState":
		return true
	}
	return false
}

// TestTheExplanationOnlyGrew is what "v stays 1" means for the token's
// explanation, as TestTheAnswerOnlyGrew is for the answer: every document
// the goldens and the policy corpus hold, explained for each token, with
// the rings' members taken out, is the explanation it had before the rings,
// byte for byte.
func TestTheExplanationOnlyGrew(t *testing.T) {
	before, err := os.ReadFile(filepath.Join("testdata", "before-rings", "explanations.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(before); hex.EncodeToString(sum[:]) != explanationsBeforeRings {
		t.Fatalf("the explanations from before the rings were rewritten; their digest is %x", sum)
	}
	names := slices.Sorted(maps.Keys(goldens))
	var documents []string
	for _, name := range names {
		if path := goldens[name]; path != "" {
			documents = append(documents, path)
		} else {
			documents = append(documents, grantCase(t, name))
		}
	}
	policies, err := filepath.Glob(filepath.Join(testdata, "policies", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	documents = append(documents, policies...)
	lines := bytes.SplitAfter(before, []byte("\n"))
	lines = lines[:len(lines)-1] // the empty remainder after the last newline
	if len(lines) != len(documents)*len(beforeRingsTokens) {
		t.Fatalf("%d explanations from before the rings for %d documents and %d tokens", len(lines), len(documents), len(beforeRingsTokens))
	}
	stripped, reread := 0, 0
	for i, document := range documents {
		for j, token := range beforeRingsTokens {
			got := ask(t, "--json", "--token", token, document)
			if got.code != 0 {
				t.Fatalf("%s, token %d: exit %d, %s", document, j+1, got.code, got.stderr)
			}
			now, ends := bytes.CutSuffix([]byte(got.stdout), []byte("\n"))
			was, wasEnds := bytes.CutSuffix(lines[i*len(beforeRingsTokens)+j], []byte("\n"))
			if !ends || !wasEnds {
				t.Fatalf("%s, token %d: an explanation does not end in the newline --json writes", document, j+1)
			}
			without, removed, err := withoutMembers(now, explanationField)
			if err != nil {
				t.Fatalf("%s, token %d: %v", document, j+1, err)
			}
			why, again := explanationReadAgain(t, document, token)
			if err := grewOnly(why, again, without, was); err != nil {
				t.Errorf("%s, token %d: without the rings' members the explanation %v:\n now    %s\n before %s", document, j+1, err, without, was)
			}
			if again {
				reread++
			}
			stripped += removed
		}
	}
	if stripped == 0 {
		t.Fatal("no explanation carried a member of the rings'; the comparison held nothing new apart")
	}
	t.Logf("%d explanations equal their explanations from before the rings, %d read again lost no member, %d members of the rings' taken out", len(lines)-reread, reread, stripped)
}

// readAgain are the documents the engine reads differently since the
// answers from before the rings were recorded, by path, each with what
// changed. A condition on a key AWS does not document for the issuer's
// tokens was read as a constraint on the claim of its name; it is now read
// as not read, with a note naming the key, which is how every other
// constraint the engine cannot evaluate is read. The keys AWS documents are
// read for every issuer the census records them for, not GitHub's alone,
// and each from the claim AWS reads it from: aud from azp, or from aud when
// a token sets no azp, so a witness that carries its audience in aud sets
// no azp and its caption says why.
var readAgain = map[string]string{
	filepath.Join("..", "..", "internal", "report", "testdata", "escapes.json"):       "its key runner<ESC>[1menvironment is not one AWS documents for GitHub's tokens",
	filepath.Join(testdata, "policies", "09-unrecognised-operator.json"):              "its keys repository_visibility, run_attempt, iat, runner_ip and jti are not ones AWS documents for GitHub's tokens",
	filepath.Join(testdata, "policies", "11-principal-shapes.json"):                   "its condition on Google's aud is read, the census recording the keys AWS documents for Google's tokens",
	filepath.Join(testdata, "policies", "22-service-and-federated-share-a-host.json"): "its conditions on an identity pool's keys are read, the census recording the keys AWS documents for them",
}

// issuedTokensReadAgain are the documents whose explanation is read again
// for a token that names its issuer, and only for one: a token an identity
// provider issued is not presented through a grant of an AWS principal or
// a service, which read it before as any token. What names no issuer is
// read on its claims alone, as before.
var issuedTokensReadAgain = map[string]bool{
	filepath.Join(testdata, "policies", "14-anyone-is-scoped-by-the-assume-action.json"): true,
	filepath.Join(testdata, "policies", "15-role-session-principal.json"):                true,
	filepath.Join(testdata, "policies", "18-service-condition-keys.json"):                true,
	filepath.Join(testdata, "policies", "23-values-that-are-not-principals.json"):        true,
}

// deniesNotApplied are the documents holding a Deny the parser could not
// fully evaluate, and so did not apply, each with the tokens the Deny may
// name, counted from 1 in beforeRingsTokens: a token of the Deny's issuer,
// or one that names none, which is read on its claims alone. What such a
// Deny refuses is not known, so it may refuse the token, which is then not
// proven admitted; it read before as a Deny that does not refuse it.
var deniesNotApplied = map[string][]int{
	filepath.Join(testdata, "policies", "13-stringlike-star-requires-presence.json"):     {1, 3},
	filepath.Join(testdata, "policies", "14-anyone-is-scoped-by-the-assume-action.json"): {3},
	filepath.Join(testdata, "policies", "15-role-session-principal.json"):                {3},
	filepath.Join(testdata, "policies", "16-duplicate-statement-member.json"):            {1, 3},
	filepath.Join(testdata, "policies", "17-operator-block-without-keys.json"):           {1, 3},
	filepath.Join(testdata, "policies", "18-service-condition-keys.json"):                {3},
	filepath.Join(testdata, "policies", "19-keys-beyond-ascii-case.json"):                {1, 3},
	filepath.Join(testdata, "policies", "23-values-that-are-not-principals.json"):        {3},
}

// deniesNamingClaims are the documents holding a Deny the parser did not
// apply whose conditions name a claim. The explanation lists each such
// claim as not evaluated, with the note that kept it from being read, for
// every token; it listed them before as claims the Deny does not name.
var deniesNamingClaims = map[string]bool{
	filepath.Join(testdata, "policies", "13-stringlike-star-requires-presence.json"): true,
	filepath.Join(testdata, "policies", "16-duplicate-statement-member.json"):        true,
	filepath.Join(testdata, "policies", "19-keys-beyond-ascii-case.json"):            true,
}

// explanationReadAgain is why a document's explanation for token was read
// again, and whether it was.
func explanationReadAgain(t *testing.T, document, token string) (string, bool) {
	t.Helper()
	if why, again := readAgain[document]; again {
		return why, true
	}
	if slices.Contains(deniesNotApplied[document], slices.Index(beforeRingsTokens, token)+1) {
		return "it holds a Deny that was not applied and may refuse the token", true
	}
	if deniesNamingClaims[document] {
		return "it holds a Deny that was not applied, and lists the claims the Deny's conditions name as not evaluated", true
	}
	if !issuedTokensReadAgain[document] {
		return "", false
	}
	payload := []byte(token)
	if parts := strings.Split(token, "."); len(parts) == 3 {
		decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		payload = decoded
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	_, issued := claims["iss"]
	return "a token an identity provider issued is not presented through its grants of AWS principals or services", issued
}

// answersReadAgain are the documents whose answer alone the engine words
// differently since, a token's explanation of them being what it was: each
// grant names aud and carries a witness, which carries the audience in aud
// and sets no azp, and the witness's caption now says so.
var answersReadAgain = map[string]bool{
	filepath.Join(testdata, "grants", "01-one-repo-one-branch", "aws.json"):         true,
	filepath.Join(testdata, "grants", "02-one-repo-any-branch", "aws.json"):         true,
	filepath.Join(testdata, "grants", "03-whole-organisation", "aws.json"):          true,
	filepath.Join(testdata, "grants", "04-immutable-subject", "aws.json"):           true,
	filepath.Join(testdata, "grants", "05-repository-id", "aws.json"):               true,
	filepath.Join(testdata, "grants", "06-unconstrained", "aws.json"):               true,
	filepath.Join(testdata, "grants", "07-expressible-by-one-provider", "aws.json"): true,
}

// answerReadAgain is why a document's answer was read again, and whether it
// was.
func answerReadAgain(document string) (string, bool) {
	if answersReadAgain[document] {
		return "its witness carries the audience in aud and sets no azp, which AWS would read for aud in its place, and the caption says so", true
	}
	why, again := readAgain[document]
	return why, again
}

// grewOnly holds an answer, its rings' members taken out, to the one the
// same document had before the rings: byte for byte, or, for a document
// the engine reads differently since, by its members, since its values are
// the new reading's: every member it held it still holds, so a field
// renamed, removed or moved still shows, and a member the schema already
// had may newly appear, as a constraint's reason does beside a claim no
// longer read. A member the schema writes only when it holds a value may
// go, as a note number does beside a claim that is now read. A document
// listed as read again whose answer did not change is listed for nothing,
// and says so.
func grewOnly(why string, again bool, now, before []byte) error {
	switch {
	case !again && !bytes.Equal(now, before):
		return errors.New("is not what it was")
	case !again:
		return nil
	case bytes.Equal(now, before):
		return fmt.Errorf("is what it was, although it is listed as read again because %s", why)
	}
	was, err := memberPaths(before)
	if err != nil {
		return err
	}
	is, err := memberPaths(now)
	if err != nil {
		return err
	}
	for path := range was {
		if !is[path] && !writtenWhenSet[path[strings.LastIndex(path, ".")+1:]] {
			return fmt.Errorf("no longer holds %s, which the new reading, where %s, leaves as it was", path, why)
		}
	}
	return nil
}

// writtenWhenSet are the member names the answer and the explanation write
// only when they hold a value, wherever the schema declares them.
var writtenWhenSet = omittedWhenEmpty(reflect.TypeOf(report.Answer{}), reflect.TypeOf(report.Explanation{}))

// omittedWhenEmpty is the JSON names every field of the types, and of the
// types they hold, declares omitempty and none declares without it.
func omittedWhenEmpty(types ...reflect.Type) map[string]bool {
	omitted, always := map[string]bool{}, map[string]bool{}
	seen := map[reflect.Type]bool{}
	var walk func(t reflect.Type)
	walk = func(t reflect.Type) {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct || seen[t] {
			return
		}
		seen[t] = true
		for i := range t.NumField() {
			f := t.Field(i)
			name, options, _ := strings.Cut(f.Tag.Get("json"), ",")
			if !f.IsExported() || name == "" || name == "-" {
				continue
			}
			if options == "omitempty" {
				omitted[name] = true
			} else {
				always[name] = true
			}
			walk(f.Type)
		}
	}
	for _, t := range types {
		walk(t)
	}
	for name := range always {
		delete(omitted, name)
	}
	return omitted
}

// memberPaths are the paths of every object member of a JSON document: the
// keys from the top, each after a dot, with [] for an array's element.
func memberPaths(doc []byte) (map[string]bool, error) {
	var v any
	if err := json.Unmarshal(doc, &v); err != nil {
		return nil, err
	}
	paths := map[string]bool{}
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch v := v.(type) {
		case map[string]any:
			for k, member := range v {
				paths[path+"."+k] = true
				walk(path+"."+k, member)
			}
		case []any:
			for _, element := range v {
				walk(path+"[]", element)
			}
		}
	}
	walk("", v)
	return paths, nil
}

// withoutMembers is a JSON document written compactly, as the engine
// writes one, with every object member whose path drop names taken out and
// every other byte as it was. A path is the keys from the top, each after
// a dot, with [] for an array's element.
func withoutMembers(doc []byte, drop func(path string) bool) ([]byte, int, error) {
	s := &stripper{in: doc, drop: drop}
	if err := s.value(""); err != nil {
		return nil, 0, err
	}
	if s.at != len(doc) {
		return nil, 0, fmt.Errorf("%d bytes after the document", len(doc)-s.at)
	}
	return s.out, s.removed, nil
}

type stripper struct {
	in, out []byte
	at      int
	removed int
	drop    func(string) bool
}

func (s *stripper) value(path string) error {
	if s.at >= len(s.in) {
		return errors.New("the document ends where a value belongs")
	}
	switch s.in[s.at] {
	case '{':
		return s.object(path)
	case '[':
		return s.array(path)
	case '"':
		s.out = append(s.out, s.in[s.at:s.stringEnd()]...)
		s.at = s.stringEnd()
		return nil
	}
	// a number, true, false or null: letters, digits and the signs and point
	// of a number, and nothing a document's structure is written with
	start := s.at
	for s.at < len(s.in) && (s.in[s.at] >= 'a' && s.in[s.at] <= 'z' || s.in[s.at] >= '0' && s.in[s.at] <= '9' || strings.ContainsRune(".+-E", rune(s.in[s.at]))) {
		s.at++
	}
	if start == s.at {
		return fmt.Errorf("no value at byte %d", start)
	}
	s.out = append(s.out, s.in[start:s.at]...)
	return nil
}

// stringEnd is the index after the string that starts at s.at.
func (s *stripper) stringEnd() int {
	for i := s.at + 1; i < len(s.in); i++ {
		switch s.in[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return len(s.in)
}

func (s *stripper) object(path string) error {
	s.out = append(s.out, '{')
	s.at++
	written := 0
	for i := 0; s.at < len(s.in) && s.in[s.at] != '}'; i++ {
		if i > 0 {
			if s.in[s.at] != ',' {
				return fmt.Errorf("no comma at byte %d", s.at)
			}
			s.at++
		}
		if s.at >= len(s.in) || s.in[s.at] != '"' {
			return fmt.Errorf("no key at byte %d", s.at)
		}
		end := s.stringEnd()
		key := string(s.in[s.at+1 : end-1])
		keyBytes := s.in[s.at:end]
		s.at = end
		if s.at >= len(s.in) || s.in[s.at] != ':' {
			return fmt.Errorf("no colon at byte %d", s.at)
		}
		s.at++
		mark := len(s.out)
		if written > 0 {
			s.out = append(s.out, ',')
		}
		s.out = append(s.out, keyBytes...)
		s.out = append(s.out, ':')
		if err := s.value(path + "." + key); err != nil {
			return err
		}
		if s.drop(path + "." + key) {
			s.out = s.out[:mark]
			s.removed++
			continue
		}
		written++
	}
	if s.at >= len(s.in) {
		return errors.New("an object is not closed")
	}
	s.out = append(s.out, '}')
	s.at++
	return nil
}

func (s *stripper) array(path string) error {
	s.out = append(s.out, '[')
	s.at++
	for i := 0; s.at < len(s.in) && s.in[s.at] != ']'; i++ {
		if i > 0 {
			if s.in[s.at] != ',' {
				return fmt.Errorf("no comma at byte %d", s.at)
			}
			s.out = append(s.out, ',')
			s.at++
		}
		if err := s.value(path + "[]"); err != nil {
			return err
		}
	}
	if s.at >= len(s.in) {
		return errors.New("an array is not closed")
	}
	s.out = append(s.out, ']')
	s.at++
	return nil
}

// TestWithoutMembers holds the stripper the additivity test rests on to
// what it must do, so that the comparison is not made by a stripper that
// agrees with anything: members taken out at their paths only, at the
// start, the middle and the end of an object, inside arrays of objects, a
// string holding every character that could be read as structure left
// alone, and a document the engine does not write refused.
func TestWithoutMembers(t *testing.T) {
	doc := `{"a":1,"b":{"c":"x\"}{,","d":[true,null]},"e":[{"f":4,"g":5},{"g":6,"f":7}],"g":"g"}`
	drop := func(p string) bool { return p == ".a" || p == ".b.d" || p == ".e[].g" }
	got, removed, err := withoutMembers([]byte(doc), drop)
	if want := `{"b":{"c":"x\"}{,"},"e":[{"f":4},{"f":7}],"g":"g"}`; err != nil || string(got) != want || removed != 4 {
		t.Errorf("stripped to %s, %d removed, %v; want %s", got, removed, err, want)
	}
	if got, removed, err := withoutMembers([]byte(doc), func(string) bool { return false }); err != nil || string(got) != doc || removed != 0 {
		t.Errorf("stripping nothing changed the document: %s, %d, %v", got, removed, err)
	}
	for _, bad := range []string{`{"a": 1}`, `{"a":1`, `[1,2`, `{"a":1}x`, `{"a"1}`, `{"a":1"b":2}`, `[1 2]`, `{"a":}`, ``, `{,"a":1}`, `{a:1}`, `{"a":1,}`} {
		if _, _, err := withoutMembers([]byte(bad), drop); err == nil {
			t.Errorf("%q was read", bad)
		}
	}
}

// TestOwnerIsRepeatableAndOneLineEach: --owner declares one owner each
// time it is given, in any position, and the JSON is the engine's own
// bytes for the owners joined a line each; an owner with a line break in
// it is a command line this command does not take.
func TestOwnerIsRepeatableAndOneLineEach(t *testing.T) {
	path, _ := ringsCase(t, "01-branch-pin-and-owner-prefix")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--json", "--owner", "github:acme", "--owner", "aws:111122223333", path},
		{"--json", path, "--owner", "aws:111122223333", "--owner=github:acme"},
	} {
		got := ask(t, args...)
		want := string(report.AdmitsFor(raw, []byte(strings.Join(ownersIn(args), "\n")))) + "\n"
		if got.code != 0 || got.stdout != want {
			t.Errorf("%v: exit %d\n%s", args, got.code, got.stdout)
		}
		if !strings.Contains(got.stdout, `"normalised":["aws:111122223333","github:acme"]`) {
			t.Errorf("%v: the owners are not echoed:\n%s", args, got.stdout)
		}
	}
	token := `{"iss":"https://token.actions.githubusercontent.com","aud":"sts.amazonaws.com","sub":"repo:acme/infra:ref:refs/heads/main"}`
	if got := ask(t, "--json", "--owner", "github:acme", "--token", token, path); got.stdout != string(report.ExplainFor(raw, []byte(token), []byte("github:acme")))+"\n" {
		t.Errorf("--owner with --token is not the engine's explanation:\n%s", got.stdout)
	}
	for _, owner := range []string{"github:acme\ngithub:evil", "github:acme\rgithub:evil"} {
		got := ask(t, "--owner", owner, path)
		if got.code != 2 || got.stdout != "" || !strings.Contains(got.stderr, "an owner is one line") {
			t.Errorf("an owner holding a line break: exit %d, stdout %q, stderr %q", got.code, got.stdout, got.stderr)
		}
	}
	tooMany := []string{}
	for range 65 {
		tooMany = append(tooMany, "--owner", "github:o")
	}
	got := ask(t, append(tooMany, path)...)
	want := report.AnswerFor(raw, []byte(strings.TrimSuffix(strings.Repeat("github:o\n", 65), "\n"))).Error
	if got.code != 1 || strings.TrimSpace(got.stderr) != want || got.stdout != want+"\n" {
		t.Errorf("65 owners: exit %d, stdout %q, stderr %q, want exit 1 and %q", got.code, got.stdout, got.stderr, want)
	}
}

// ownersIn is the values of every --owner in a command line, in order.
func ownersIn(args []string) []string {
	var out []string
	for i, a := range args {
		switch {
		case a == "--owner" && i+1 < len(args):
			out = append(out, args[i+1])
		case strings.HasPrefix(a, "--owner="):
			out = append(out, strings.TrimPrefix(a, "--owner="))
		}
	}
	return out
}

// TestExplainListsTheOwnersItRead: --explain names every owner the command
// was given, as given, before it answers, and names none when none was.
func TestExplainListsTheOwnersItRead(t *testing.T) {
	path, _ := ringsCase(t, "01-branch-pin-and-owner-prefix")
	got := ask(t, "--explain", "--owner", "github:acme", "--owner", "saml:arn:aws:iam::123456789012:saml-provider/Ven\x1b[31mdor", path)
	for _, want := range []string{`reads the owner "github:acme" from --owner`, `reads the owner "saml:arn:aws:iam::123456789012:saml-provider/Ven\x1b[31mdor" from --owner`} {
		if !strings.Contains(got.stderr, want) {
			t.Errorf("--explain does not say %q:\n%s", want, got.stderr)
		}
	}
	if strings.ContainsRune(got.stderr, 0x1b) {
		t.Errorf("--explain put an escape on the terminal:\n%q", got.stderr)
	}
	if plain := ask(t, "--explain", path); strings.Contains(plain.stderr, "--owner") {
		t.Errorf("--explain names owners nobody gave:\n%s", plain.stderr)
	}
	if !slices.Contains(strings.Split(got.stderr, "\n"), "  consults NO_COLOR, and no other environment variable") {
		t.Errorf("--explain lost what it said before:\n%s", got.stderr)
	}
}

// TestExplainCitesTheReadingOfAWS: the face of "*" is placed at Anyone on
// the engine's reading of two AWS sentences, and a line of cloud services
// holding a service the parser's table of intermediaries lists rests on
// that service's sentences. --explain prints, after the answer and on
// standard error, the heading and the quotes the answer carries for each,
// and nothing it composes itself; a document that rests on no such reading
// has nothing quoted, and without --explain nothing is added.
func TestExplainCitesTheReadingOfAWS(t *testing.T) {
	for _, c := range []struct {
		name  string
		lines int
	}{
		// a heading, the two sentences and their page
		{"07-anyone-on-web-identity", 5},
		// a heading, and IAM Roles Anywhere's four sentences and their pages
		{"66-roles-anywhere-documented-policy", 9},
	} {
		path, _ := ringsCase(t, c.name)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var answer struct {
			Rings  []report.Row `json:"rings"`
			Beside []report.Row `json:"beside"`
		}
		if err := json.Unmarshal(report.Admits(raw), &answer); err != nil {
			t.Fatal(err)
		}
		var cited []string
		for _, r := range append(answer.Rings, answer.Beside...) {
			if len(r.Citations) == 0 {
				continue
			}
			if r.CitationsHeading == "" {
				t.Fatalf("%s: the answer quotes AWS under no heading of its own", c.name)
			}
			cited = append(cited, "  "+r.CitationsHeading)
			for _, q := range r.Citations {
				cited = append(cited, `    "`+q.Quote+`"`, "      "+q.Source)
			}
		}
		if len(cited) != c.lines {
			t.Fatalf("%s: the answer carries %d lines to cite, want %d", c.name, len(cited), c.lines)
		}
		got := ask(t, "--explain", path)
		if got.code != 0 || got.stdout != report.AnswerOf(raw).Text(report.Options{}) {
			t.Errorf("%s: --explain changed the answer: exit %d\n%s", c.name, got.code, got.stdout)
		}
		lines := strings.Split(strings.TrimSuffix(got.stderr, "\n"), "\n")
		at := slices.Index(lines, "cloudarq admits, after it answers:")
		if at < 0 || !slices.Equal(lines[at+1:], cited) {
			t.Errorf("%s: --explain does not print the answer's reading, and only it:\n%s", c.name, got.stderr)
		}
		if plain := ask(t, path); plain.stderr != "" {
			t.Errorf("%s: without --explain the command wrote to standard error:\n%s", c.name, plain.stderr)
		}
	}
	other, _ := ringsCase(t, "11-cognito-guests")
	if got := ask(t, "--explain", other); strings.Contains(got.stderr, "after it answers") {
		t.Errorf("a document resting on no reading quotes one:\n%s", got.stderr)
	}
}

// TestNoServiceIsCalledNotAnOutsideIdentity: some services assume a role
// for identities outside IAM and hand them its session, as IAM Roles
// Anywhere does for whoever holds a certificate its trust anchor accepts,
// and nobody surveyed the rest, so no answer says of any service that it
// is not an outside identity. The trust policies under testdata's policies,
// grants and rings, and the escape fixture, are asked, in text and in JSON,
// and the count says they were.
func TestNoServiceIsCalledNotAnOutsideIdentity(t *testing.T) {
	docs := corpus(t)
	for _, name := range ringsCaseNames(t) {
		path, _ := ringsCase(t, name)
		docs[path] = nil
	}
	examined := 0
	for path := range docs {
		for _, args := range [][]string{{path}, {"--json", path}} {
			got := ask(t, args...)
			if got.code != 0 || got.stderr != "" {
				t.Fatalf("%v: exit %d, %s", args, got.code, got.stderr)
			}
			examined++
			for _, words := range []string{"not an external identity", "not an outside identity"} {
				if strings.Contains(got.stdout, words) {
					t.Errorf("%v says %q", args, words)
				}
			}
		}
	}
	// 24 policies, 7 grants, the escape fixture and 75 rings cases: at
	// least 107 documents, in text and in JSON
	if examined < 214 {
		t.Fatalf("%d answers examined, want at least 214", examined)
	}
	t.Logf("%d answers examined", examined)
}

// TestExplainPrintsTheReportsWordsAlone: everything --explain writes is a
// line internal/report composed, before the answer and after it, and the
// command adds none of its own, so that no sentence is composed outside the
// one place every answer's words come from.
func TestExplainPrintsTheReportsWordsAlone(t *testing.T) {
	path, _ := ringsCase(t, "07-anyone-on-web-identity")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	token := `{"iss":"https://token.actions.githubusercontent.com","sub":"repo:acme/infra:ref:refs/heads/main"}`
	for _, c := range []struct {
		in           invocation
		file, token  string
		owners       []string
		answersAfter bool
	}{
		{invocation{args: []string{"admits", "--explain", path}}, path, "", nil, true},
		{invocation{args: []string{"admits", "--explain", "--owner", "github:acme", "--owner", "aws:111122223333", path}}, path, "", []string{"github:acme", "aws:111122223333"}, true},
		{invocation{args: []string{"admits", "--explain", "-"}, stdin: string(raw)}, "-", "", nil, true},
		{invocation{args: []string{"admits", "--explain", "--token", token, path}}, path, token, nil, false},
	} {
		want := report.ExplainPlan(c.file, c.token, c.owners)
		if c.answersAfter {
			want = append(want, report.AnswerFor(raw, []byte(strings.Join(c.owners, "\n"))).ExplainCitations()...)
		}
		got := c.in.run(t)
		if got.code != 0 || got.stderr != strings.Join(want, "\n")+"\n" {
			t.Errorf("%v: exit %d, and --explain wrote\n%s\nwhere the report's words are\n%s", c.in.args, got.code, got.stderr, strings.Join(want, "\n"))
		}
	}
}

// TestARefusedOwnerIsAnInvalidFlagValue: an --owner the engine does not read
// as an owner is a value this command does not take, as any invalid flag
// value is: exit 2, the flag package's own line naming the value and the
// engine's reason for refusing it, the usage once, and no answer. A flag
// that declares nothing, blank or all spaces, is one, since a script that
// passed an empty variable meant to declare someone. The usage says so.
func TestARefusedOwnerIsAnInvalidFlagValue(t *testing.T) {
	path, _ := ringsCase(t, "01-branch-pin-and-owner-prefix")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// an owner holding a letter beyond ASCII is echoed in ASCII, as every
	// build of the command quotes it: U+A7CB is printable in Unicode 17 and
	// not in Unicode 15, which the standard library's quoting would follow
	for _, owner := range []string{"gitlab:acme", "bogus", "github:acme/infra", "aws:12", "", "   ", "github:acme\ua7cb", "github:acm\u00e9"} {
		var why string
		if strings.TrimSpace(owner) != "" {
			var echo struct {
				Declarations struct {
					RefusedLines []struct {
						Sentence string `json:"sentence"`
					} `json:"refusedLines"`
				} `json:"declarations"`
			}
			if err := json.Unmarshal(report.AdmitsFor(raw, []byte(owner)), &echo); err != nil || len(echo.Declarations.RefusedLines) != 1 {
				t.Fatalf("%q is not refused by the engine: %v", owner, err)
			}
			why = echo.Declarations.RefusedLines[0].Sentence
		}
		for _, args := range [][]string{{"--owner", owner, path}, {"--json", "--owner", "github:acme", "--owner", owner, path}} {
			got := ask(t, args...)
			line, _, _ := strings.Cut(got.stderr, "\n")
			prefix := "invalid value " + strconv.QuoteToASCII(owner) + " for flag -owner: "
			if got.code != 2 || got.stdout != "" || !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, why) || len(line) == len(prefix) || strings.Count(got.stderr, "usage: cloudarq admits") != 1 {
				t.Errorf("%q: exit %d, stdout %q, stderr %q; want exit 2, %q and the engine's reason %q, and the usage", args, got.code, got.stdout, got.stderr, prefix, why)
			}
		}
	}
	// an owner past the engine's bound for a line is not refused as a
	// value: the whole declaration is, as the answer's error, as a
	// document past its bound is
	long := "github:" + strings.Repeat("a", 600)
	over := ask(t, "--owner", long, path)
	if want := report.AnswerFor(raw, []byte(long)).Error; want == "" || over.code != 1 || strings.TrimSpace(over.stderr) != want || over.stdout != want+"\n" {
		t.Errorf("an owner of %d bytes: exit %d, stdout %q, stderr %q, want exit 1 and %q", len(long), over.code, over.stdout, over.stderr, want)
	}
	usage := strings.Join(strings.Fields(invocation{args: nil}.run(t).stderr), " ")
	if !strings.Contains(usage, "an --owner the engine does not read as an owner") {
		t.Errorf("the usage does not say that an owner the engine refuses exits 2:\n%s", usage)
	}
}
