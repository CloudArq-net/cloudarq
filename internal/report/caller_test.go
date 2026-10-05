package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"pgregory.net/rapid"
)

// callerCase is one case of testdata/callers/cases.json: a refusal's
// message, as AWS words it or forged, and the message as it must read
// without the person who made the call.
type callerCase struct {
	ID      string `json:"id"`
	Shape   string `json:"shape"`
	Message string `json:"message"`
	Want    string `json:"want"`
	Source  string `json:"source"`
}

// callerShapes is how many cases of each shape the table holds. A loader
// that read fewer, or a shape gone from the table, would leave a form of
// the grammar unheld while every case left passed.
var callerShapes = map[string]int{
	"forged": 22, "assumed-role": 7, "iam-user": 6, "no-arn": 4, "iam-user-path": 4, "role-caller": 4,
	"assumed-role-sso": 3, "mfa": 3, "other-arn": 3, "federated-user": 2, "unanswered": 2, "u2f": 1, "root": 1,
}

// The table's size, and how many of its cases the strip must change.
const (
	callerCaseCount    = 62
	callerCasesChanged = 42
)

const callerCases = testdata + "/callers/cases.json"

// callerTable reads the table, refusing a member it does not know,
// anything after the list, a case with an empty field, an id twice, and
// counts other than callerShapes'.
func callerTable(t testing.TB) []callerCase {
	t.Helper()
	raw, err := os.ReadFile(callerCases)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var cases []callerCase
	if err := decoder.Decode(&cases); err != nil {
		t.Fatalf("%s: %v", callerCases, err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		t.Fatalf("%s holds something after its list of cases (%v)", callerCases, err)
	}
	shapes, ids, changed := map[string]int{}, map[string]bool{}, 0
	for _, c := range cases {
		if c.ID == "" || c.Shape == "" || c.Message == "" || c.Want == "" || c.Source == "" {
			t.Fatalf("%s: a case with an empty field: %+v", callerCases, c)
		}
		if ids[c.ID] {
			t.Fatalf("%s: the id %s twice", callerCases, c.ID)
		}
		ids[c.ID] = true
		shapes[c.Shape]++
		if c.Want != c.Message {
			changed++
		}
	}
	if len(cases) != callerCaseCount || !maps.Equal(shapes, callerShapes) || changed != callerCasesChanged {
		t.Fatalf("%s holds %d cases of shapes %v, %d of them changed by the strip; it holds %d of shapes %v, %d changed",
			callerCases, len(cases), shapes, changed, callerCaseCount, callerShapes, callerCasesChanged)
	}
	return cases
}

// TestEveryCaseOfTheCallerTableReadsAsItsWant holds the strip to the
// table, byte for byte, and each want to itself: a message already
// stripped is stripped to the same text.
func TestEveryCaseOfTheCallerTableReadsAsItsWant(t *testing.T) {
	cases := callerTable(t)
	matched, changed, fixed := 0, 0, 0
	for _, c := range cases {
		if got := withoutPeople(c.Message); got != c.Want {
			t.Errorf("%s (%s):\n got %+q\nwant %+q", c.ID, c.Shape, got, c.Want)
		} else {
			matched++
			if got != c.Message {
				changed++
			}
		}
		if again := withoutPeople(c.Want); again != c.Want {
			t.Errorf("%s: its want, stripped, reads %+q", c.ID, again)
		} else {
			fixed++
		}
	}
	t.Logf("%d of %d cases read as their want, %d of them changed; %d wants unchanged when stripped again", matched, len(cases), changed, fixed)
}

// awsNameClasses are the characters AWS allows in a user, session, federated
// user and MFA device name, [\w+=,.@-], by class: 69 in all.
var awsNameClasses = []string{
	"abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789",
	"_", "+", "=", ",", ".", "@", "-",
}

// awsPathCharacters are the characters a path may hold between its slashes,
// U+0021 to U+007E but the slash.
var awsPathCharacters = func() string {
	var b strings.Builder
	for c := byte('!'); c <= '~'; c++ {
		if c != '/' {
			b.WriteByte(c)
		}
	}
	return b.String()
}()

var (
	drawnPartitions = []string{"aws", "aws-cn", "aws-us-gov"}
	drawnAccounts   = []string{"123456789012", "777788889999", ""}
	personARNKinds  = []string{"assumed-role", "user", "federated-user", "u2f", "mfa"}
	keptARNKinds    = []string{"role", "role-path-of-types", "root", "policy", "group", "other-service", "region-filled-in",
		"empty-partition", "missing-field", "assumed-role-without-session"}
	// arnEnds are what may follow an ARN: each is a byte or a character
	// outside U+0021 to U+007E. The end of the message, "", follows the
	// last ARN alone.
	arnEnds = []string{" ", "\t", "\n", "\r\n", "\x00", "\x7f", "\u00a0", "\u2019", "\U0001F600"}
	// proseAround is the text around the ARNs: none of it holds "arn:",
	// and no two of these joined make it, since none begins with a colon.
	proseAround = []string{
		"User: ", " is not authorized to perform: ", "iam:ListRoles", " on resource: ",
		" because no identity-based policy allows the ", " action", " with an explicit deny in a service control policy: ",
		"Warn", "ARN", "Arn:", "barn", "arn", "user/Jane", "assumed-role/R/s", "(removed)", "café", "—", ",", ".",
	}
)

// strippedDraws counts what the generators drew, so a property can say it
// examined each kind of thing it claims to hold.
type strippedDraws struct {
	classes    [10]int
	persons    map[string]int
	kept       map[string]int
	partitions map[string]int
	ends       map[string]int
	paths      int
	emptyNames int
	survivals  int
}

func newDraws() *strippedDraws {
	return &strippedDraws{persons: map[string]int{}, kept: map[string]int{}, partitions: map[string]int{}, ends: map[string]int{}}
}

// missing names whatever the generators never drew.
func (d *strippedDraws) missing() []string {
	var gone []string
	for i, n := range d.classes {
		if n == 0 {
			gone = append(gone, fmt.Sprintf("name characters %+q", awsNameClasses[i]))
		}
	}
	for _, set := range []struct {
		what  string
		all   []string
		count map[string]int
	}{
		{"the ARN of", personARNKinds, d.persons},
		{"the ARN left alone", keptARNKinds, d.kept},
		{"the partition", drawnPartitions, d.partitions},
		{"the end", append(slices.Clone(arnEnds), ""), d.ends},
	} {
		for _, k := range set.all {
			if set.count[k] == 0 {
				gone = append(gone, fmt.Sprintf("%s %+q", set.what, k))
			}
		}
	}
	if d.paths == 0 {
		gone = append(gone, "a path")
	}
	if d.emptyNames == 0 {
		gone = append(gone, "an empty name")
	}
	return gone
}

// genName draws a name of AWS's characters, each class counted when count
// is set, and an empty name counted too.
func genName(t *rapid.T, d *strippedDraws, minLength, maxLength int, label string, count bool) string {
	n := rapid.IntRange(minLength, maxLength).Draw(t, label+" length")
	var b strings.Builder
	for range n {
		class := rapid.IntRange(0, len(awsNameClasses)-1).Draw(t, label+" class")
		chars := awsNameClasses[class]
		b.WriteByte(chars[rapid.IntRange(0, len(chars)-1).Draw(t, label+" character")])
		if count {
			d.classes[class]++
		}
	}
	if count && n == 0 {
		d.emptyNames++
	}
	return b.String()
}

// genPath draws a path of up to three segments of characters, each
// followed by a slash, counted in d when d is not nil.
func genPath(t *rapid.T, d *strippedDraws, characters string) string {
	segments := rapid.IntRange(0, 3).Draw(t, "path segments")
	var b strings.Builder
	for range segments {
		for range rapid.IntRange(1, 8).Draw(t, "segment length") {
			b.WriteByte(characters[rapid.IntRange(0, len(characters)-1).Draw(t, "path character")])
		}
		b.WriteByte('/')
	}
	if segments > 0 && d != nil {
		d.paths++
	}
	return b.String()
}

// removedToken is the token as the table spells it, so a generator's
// wants never read it from the code under test.
const removedToken = "(removed)"

// genPerson draws the ARN of one of the five kinds the strip replaces: the
// ARN, what it must read, and the text the strip removes from it.
func genPerson(t *rapid.T, d *strippedDraws) (arn, want, removed string) {
	partition := rapid.SampledFrom(drawnPartitions).Draw(t, "partition")
	account := rapid.SampledFrom(drawnAccounts).Draw(t, "account")
	kind := rapid.SampledFrom(personARNKinds).Draw(t, "kind")
	d.persons[kind]++
	d.partitions[partition]++
	var service, head string
	switch kind {
	case "assumed-role":
		service, head = "sts", "assumed-role/"+genName(t, d, 1, 64, "role", false)+"/"
		removed = genName(t, d, 0, 70, "session", true)
	case "user":
		service, head = "iam", "user/"
		removed = genPath(t, d, awsPathCharacters) + genName(t, d, 0, 64, "user", true)
	case "federated-user":
		service, head = "sts", "federated-user/"
		removed = genName(t, d, 0, 32, "federated user", true)
	case "u2f":
		service, head = "iam", "u2f/"
		removed = "user/" + genName(t, d, 0, 64, "u2f user", true) + "/" + genName(t, d, 1, 16, "u2f key", false)
	case "mfa":
		service, head = "iam", "mfa/"
		removed = genPath(t, d, awsPathCharacters) + genName(t, d, 0, 64, "mfa device", true)
	}
	prefix := "arn:" + partition + ":" + service + "::" + account + ":" + head
	return prefix + removed, prefix + removedToken, removed
}

// genKept draws an ARN the strip must leave as it is.
func genKept(t *rapid.T, d *strippedDraws) string {
	partition := rapid.SampledFrom(drawnPartitions).Draw(t, "kept partition")
	account := rapid.SampledFrom(drawnAccounts).Draw(t, "kept account")
	kind := rapid.SampledFrom(keptARNKinds).Draw(t, "kept kind")
	d.kept[kind]++
	name := func(label string) string { return genName(t, d, 1, 16, label, false) }
	iam := "arn:" + partition + ":iam::" + account + ":"
	switch kind {
	case "role":
		return iam + "role/" + genPath(t, nil, strings.Join(awsNameClasses, "")) + name("role")
	case "role-path-of-types":
		return iam + "role/assumed-role/user/federated-user/u2f/mfa/" + name("role")
	case "root":
		return iam + "root"
	case "policy":
		return iam + "policy/" + name("policy")
	case "group":
		return iam + "group/" + name("group")
	case "other-service":
		return "arn:" + partition + ":identitystore:::user/" + name("identity store user")
	case "region-filled-in":
		return "arn:" + partition + ":sts:us-east-1:" + account + ":assumed-role/" + name("role") + "/" + name("session")
	case "empty-partition":
		return "arn::iam::" + account + ":user/" + name("user")
	case "missing-field":
		return "arn:" + partition + ":iam:" + account + ":user/" + name("user")
	default: // assumed-role-without-session
		return "arn:" + partition + ":sts::" + account + ":assumed-role/" + name("role")
	}
}

// genProse draws text that holds no "arn:".
func genProse(t *rapid.T) string {
	var b strings.Builder
	for range rapid.IntRange(0, 3).Draw(t, "prose pieces") {
		b.WriteString(rapid.SampledFrom(proseAround).Draw(t, "prose"))
	}
	return b.String()
}

// genMessage draws a message of one to four ARNs, people's and others',
// with text around them, glued to them or not, and what it must read once
// stripped, and the text each person's ARN loses. Every ARN ends at a
// character outside U+0021 to U+007E, or at the end of the message.
func genMessage(t *rapid.T, d *strippedDraws) (message, want string, removed []string) {
	var m, w strings.Builder
	write := func(text, stripped string) {
		m.WriteString(text)
		w.WriteString(stripped)
	}
	arns := rapid.IntRange(1, 4).Draw(t, "ARNs")
	end := ""
	for i := range arns {
		text := genProse(t)
		write(text, text)
		if rapid.Bool().Draw(t, "a person") {
			arn, stripped, gone := genPerson(t, d)
			write(arn, stripped)
			removed = append(removed, gone)
		} else {
			arn := genKept(t, d)
			write(arn, arn)
		}
		end = ""
		if i < arns-1 || rapid.Bool().Draw(t, "text after the last ARN") {
			end = rapid.SampledFrom(arnEnds).Draw(t, "end")
		}
		d.ends[end]++
		write(end, end)
	}
	if end != "" {
		text := genProse(t)
		write(text, text)
	}
	return m.String(), w.String(), removed
}

// TestNoNameSurvivesTheStrip draws messages naming people of every kind
// AWS writes, among ARNs the strip must leave alone, and holds the strip
// to what the grammar gives: every name, path and session gone and the
// token in its place, and nothing else changed. The generator must have
// drawn every class of character AWS allows in a name, each of the five
// kinds, each partition, paths, empty names, every kind of ARN left alone
// and every end, or the property held nothing of what it is named for.
func TestNoNameSurvivesTheStrip(t *testing.T) {
	d := newDraws()
	examined := 0
	rapid.Check(t, func(t *rapid.T) {
		message, want, removed := genMessage(t, d)
		examined++
		got := withoutPeople(message)
		if got != want {
			t.Fatalf("\n   message %+q\n       got %+q\n      want %+q", message, got, want)
		}
		for _, name := range removed {
			if len(name) >= 6 && !strings.Contains(want, name) {
				d.survivals++
				if strings.Contains(got, name) {
					t.Fatalf("%+q survived the strip: %+q", name, got)
				}
			}
		}
	})
	if gone := d.missing(); examined == 0 || d.survivals == 0 || len(gone) > 0 {
		t.Fatalf("over %d messages, %d names looked for, the generator never drew: %s", examined, d.survivals, strings.Join(gone, "; "))
	}
	t.Logf("%d messages, %d names looked for, %d people and %d ARNs left alone; name characters by class %v",
		examined, d.survivals, countAll(d.persons), countAll(d.kept), d.classes)
}

func countAll(counts map[string]int) int {
	n := 0
	for _, v := range counts {
		n += v
	}
	return n
}

// TestStrippingTwiceIsStrippingOnce: the token holds no "arn:" and is
// printable, so a second strip finds the same ARNs ending where they ended
// and writes the same text. A property over messages the strip never
// changed would compare nothing, so some must have changed.
func TestStrippingTwiceIsStrippingOnce(t *testing.T) {
	d := newDraws()
	examined, changed := 0, 0
	rapid.Check(t, func(t *rapid.T) {
		message, _, _ := genMessage(t, d)
		once := withoutPeople(message)
		if twice := withoutPeople(once); twice != once {
			t.Fatalf("\nmessage %+q\n   once %+q\n  twice %+q", message, once, twice)
		}
		examined++
		if once != message {
			changed++
		}
	})
	for _, c := range callerTable(t) {
		once := withoutPeople(c.Message)
		if twice := withoutPeople(once); twice != once {
			t.Fatalf("%s: once %+q, twice %+q", c.ID, once, twice)
		}
		examined++
		if once != c.Message {
			changed++
		}
	}
	if examined == 0 || changed == 0 {
		t.Fatalf("over %d messages the strip changed %d, so stripping twice was compared with nothing stripped", examined, changed)
	}
	t.Logf("%d messages, %d of them changed by the first strip and none by the second", examined, changed)
}

// noARNPieces are the text a message without an ARN is strippedDraws from: words
// that come near one, and bytes and characters of every kind, ASCII
// controls, U+007F, U+00A0, characters of two, three and four bytes, and
// a byte that is no UTF-8.
var noARNPieces = []string{
	"arn", "ARN:", "Arn:", "ar n:", "arn :", "xarn", "user/Jane", ":user/", "assumed-role/R/s", "federated-user/Bob",
	"u2f/user/John/default", "mfa/JaneMFA", "(removed)", "User: ", " is not authorized to perform: iam:ListRoles",
	":", "/", " ", "\t", "\r\n", "\x00", "\x7f", "\u00a0", "é", "\u2019", "\U0001F600", "\xff",
}

// TestAMessageWithoutAnARNIsUnchanged draws text without "arn:" and holds
// the strip to leaving it byte for byte. The text must have held each
// kind of thing that comes near an ARN, or the property said nothing of
// them.
func TestAMessageWithoutAnARNIsUnchanged(t *testing.T) {
	seen := map[string]int{}
	rapid.Check(t, func(t *rapid.T) {
		var b strings.Builder
		for range rapid.IntRange(0, 24).Draw(t, "pieces") {
			if rapid.Bool().Draw(t, "a piece") {
				b.WriteString(rapid.SampledFrom(noARNPieces).Draw(t, "piece"))
			} else {
				b.WriteByte(byte(rapid.IntRange(0, 255).Draw(t, "byte")))
			}
		}
		message := b.String()
		// A colon strippedDraws after "arn" would make an ARN; it is made a
		// semicolon, which makes none.
		for strings.Contains(message, "arn:") {
			message = strings.Replace(message, "arn:", "arn;", 1)
		}
		seen["examined"]++
		for what, holds := range map[string]bool{
			"arn":                     strings.Contains(message, "arn"),
			"a colon":                 strings.Contains(message, ":"),
			"a person's type":         strings.Contains(message, "user/") || strings.Contains(message, "assumed-role/"),
			"past U+007E":             strings.ContainsFunc(message, func(r rune) bool { return r > 0x7e }),
			"a control character":     strings.ContainsAny(message, "\x00\t\r\n\x7f"),
			"a byte that is no UTF-8": !utf8.ValidString(message),
		} {
			if holds {
				seen[what]++
			}
		}
		if got := withoutPeople(message); got != message {
			t.Fatalf("\nmessage %+q\n    got %+q", message, got)
		}
	})
	for _, what := range []string{"examined", "arn", "a colon", "a person's type", "past U+007E", "a control character", "a byte that is no UTF-8"} {
		if seen[what] == 0 {
			t.Fatalf("no message strippedDraws held %s (%v)", what, seen)
		}
	}
	t.Logf("%v", seen)
}

// FuzzWithoutPeople holds any text to four things the grammar gives:
// stripping twice is stripping once; text without "arn:" is unchanged;
// the strip adds at most 9 bytes for every 17, since the shortest ARN it
// rewrites is 16 bytes and two need a byte outside U+0021 to U+007E
// between them; and it never breaks UTF-8 that was whole. The table's
// messages and wants are its seeds.
func FuzzWithoutPeople(f *testing.F) {
	for _, c := range callerTable(f) {
		f.Add(c.Message)
		f.Add(c.Want)
	}
	f.Fuzz(func(t *testing.T, message string) {
		once := withoutPeople(message)
		if twice := withoutPeople(once); twice != once {
			t.Fatalf("\nmessage %+q\n   once %+q\n  twice %+q", message, once, twice)
		}
		if !strings.Contains(message, "arn:") && once != message {
			t.Fatalf("a message without arn: changed:\nmessage %+q\n    got %+q", message, once)
		}
		if n := len(message); len(once) > n+9*((n+1)/17) {
			t.Fatalf("%d bytes became %d, more than %d", n, len(once), n+9*((n+1)/17))
		}
		if utf8.ValidString(message) && !utf8.ValidString(once) {
			t.Fatalf("whole UTF-8 became broken: %+q", once)
		}
	})
}

// refusingBundle is a bundle as cloudarq-collect 0.2.0 wrote it, with no
// Organization member, of one role trusting policy, and refused.
func refusingBundle(t fataler, policy string, refused []any) []byte {
	b := map[string]any{
		"format": "cloudarq.collect/v1", "provider": "aws", "account": bundleAccount, "partition": "aws", "alias": "production",
		"collected_at": "2026-09-27T00:00:00Z", "collector": "cloudarq-collect 0.2.0",
		"pages": []any{map[string]any{"IsTruncated": true, "Marker": "page-2", "Roles": []any{map[string]any{
			"Path": "/", "RoleName": "deploy", "RoleId": "AROADEPLOY", "Arn": "arn:aws:iam::" + bundleAccount + ":role/deploy",
			"CreateDate": "2024-01-02T03:04:05Z", "AssumeRolePolicyDocument": policy,
		}}}},
		"refused": refused, "limits": []any{},
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return raw
}

// refusalsOf is one refusal for each case, of a call the collector makes,
// its message what text gives the case.
func refusalsOf(cases []callerCase, text func(callerCase) string) []any {
	refused := []any{}
	for i, c := range cases {
		call, code := "iam:ListRoles", "AccessDenied"
		if i%2 == 1 {
			call = "iam:ListAccountAliases"
		}
		if c.Shape == "unanswered" {
			code = "Unanswered"
		}
		refused = append(refused, map[string]any{"call": call, "code": code, "message": text(c)})
	}
	return refused
}

func messageOf(c callerCase) string { return c.Message }
func wantOf(c callerCase) string    { return c.Want }

// janeTrust is a trust policy naming a person, which the strip must never
// read: it is the account's own text, and its answer is the engine's.
const janeTrust = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/Jane"},"Action":"sts:AssumeRole"}]}`

// TestReadBundleStripsEachRefusalAsItCopiesIt reads a bundle written
// before the collector stripped anything, every case of the table one of
// its refusals: each message reads as its want, its call and code as they
// were, and bundle_sha256 is still the digest of the file as given.
func TestReadBundleStripsEachRefusalAsItCopiesIt(t *testing.T) {
	cases := callerTable(t)
	raw := refusingBundle(t, janeTrust, refusalsOf(cases, messageOf))
	b, err := ReadBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	f := findingsOf(t, raw, "")
	if len(b.Refused) != len(cases) || len(f.Refused) != len(cases) {
		t.Fatalf("%d refusals read and %d written, of %d", len(b.Refused), len(f.Refused), len(cases))
	}
	matched, stripped := 0, 0
	wants := refusalsOf(cases, wantOf)
	for i, c := range cases {
		want := wants[i].(map[string]any)
		read := BundleRefusal{Call: want["call"].(string), Code: want["code"].(string), Message: c.Want}
		if b.Refused[i] != read || f.Refused[i] != read {
			t.Errorf("%s: read %+q %+q %+q, written %+q %+q %+q; want %+q %+q %+q", c.ID, b.Refused[i].Call, b.Refused[i].Code, b.Refused[i].Message,
				f.Refused[i].Call, f.Refused[i].Code, f.Refused[i].Message, read.Call, read.Code, read.Message)
			continue
		}
		matched++
		if c.Want != c.Message {
			stripped++
		}
	}
	if f.BundleSHA256 != hexOf(raw) {
		t.Errorf("bundle_sha256 %s is not the digest of the file as given, %s", f.BundleSHA256, hexOf(raw))
	}
	t.Logf("%d of %d refusals read as their want, %d of them stripped", matched, len(cases), stripped)
}

// sameButTheDigest compares the findings of two bundles that differ in
// their refusals' messages alone: once the first's bundle_sha256 is the
// second's, the bytes must be the same.
func sameButTheDigest(named, bare []byte, owners string) (bool, string) {
	got := Findings(named, []byte(owners), "cloudarq test")
	want := Findings(bare, []byte(owners), "cloudarq test")
	digest := []byte(`"bundle_sha256":"` + hexOf(named) + `"`)
	if bytes.Count(got, digest) != 1 {
		return false, fmt.Sprintf("the findings do not name the bundle's digest once:\n%s", got)
	}
	got = bytes.Replace(got, digest, []byte(`"bundle_sha256":"`+hexOf(bare)+`"`), 1)
	if !bytes.Equal(got, want) {
		at := 0
		for at < min(len(got), len(want)) && got[at] == want[at] {
			at++
		}
		return false, fmt.Sprintf("they differ at byte %d:\n...%s...\n...%s...", at, around(got, at), around(want, at))
	}
	return true, ""
}

// rolesOf is the findings' roles, as written.
func rolesOf(t fataler, findings []byte) json.RawMessage {
	var f map[string]json.RawMessage
	if err := json.Unmarshal(findings, &f); err != nil || f["roles"] == nil {
		t.Fatalf("the findings hold no roles (%v):\n%s", err, findings)
	}
	return f["roles"]
}

// documentRead is the trust policy as a reader of the bundle reads it:
// encoding/json writes text that is no UTF-8 as U+FFFD, so the digest is
// of what the bundle holds, not of the file the policy came from.
func documentRead(t fataler, bundle []byte) []byte {
	var b struct {
		Pages []struct {
			Roles []struct {
				AssumeRolePolicyDocument string
			}
		} `json:"pages"`
	}
	if err := json.Unmarshal(bundle, &b); err != nil || len(b.Pages) != 1 || len(b.Pages[0].Roles) != 1 {
		t.Fatalf("the bundle is not of one role: %v", err)
	}
	return []byte(b.Pages[0].Roles[0].AssumeRolePolicyDocument)
}

// answersUnchanged holds one trust policy to the strip's one promise about
// answers: a bundle whose refusals name people is answered byte for byte as
// the same bundle with those refusals already stripped, the role's answer
// as the same bundle with no refusal at all, and its document_sha256 is
// the policy's own.
func answersUnchanged(t fataler, cases []callerCase, policy string) {
	named := refusingBundle(t, policy, refusalsOf(cases, messageOf))
	bare := refusingBundle(t, policy, refusalsOf(cases, wantOf))
	none := refusingBundle(t, policy, []any{})
	for _, owners := range []string{"", "aws:123456789012\ngithub:acme"} {
		if same, why := sameButTheDigest(named, bare, owners); !same {
			t.Fatalf("owners %+q: the findings of refusals naming people are not those of the same refusals stripped: %s\npolicy: %s", owners, why, clipped(policy))
		}
		got, want := rolesOf(t, Findings(named, []byte(owners), "cloudarq test")), rolesOf(t, Findings(none, []byte(owners), "cloudarq test"))
		if !bytes.Equal(got, want) {
			t.Fatalf("owners %+q: the role is answered otherwise beside refusals naming people:\n%s\n%s", owners, got, want)
		}
	}
	var f findingsShape
	if err := json.Unmarshal(Findings(named, nil, "cloudarq test"), &f); err != nil || len(f.Roles) != 1 {
		t.Fatalf("the findings do not read: %v", err)
	}
	if want := hexOf(documentRead(t, named)); f.Roles[0].DocumentSHA256 != want {
		t.Fatalf("document_sha256 %s is not the policy's, %s: the strip read the trust policy\npolicy: %s", f.Roles[0].DocumentSHA256, want, clipped(policy))
	}
}

// namesAPerson is whether text holds an ARN of a kind the strip replaces,
// read here without the strip.
func namesAPerson(text string) bool {
	for _, kind := range []string{":user/", ":assumed-role/", ":federated-user/", ":u2f/", ":mfa/"} {
		if strings.Contains(text, kind) && strings.Contains(text, "arn:") {
			return true
		}
	}
	return false
}

// TestTheStripLeavesEveryAnswerOfTheCorpusAsItWas puts each document of
// the corpus in a bundle as a role's trust policy, beside refusals naming
// people, and holds the answer to every byte it has without them. Some
// documents of the corpus name a person in their own text, and those must
// be among the examined, or the strip reaching into a trust policy was
// never looked for.
func TestTheStripLeavesEveryAnswerOfTheCorpusAsItWas(t *testing.T) {
	cases := callerTable(t)
	examined, naming := 0, 0
	for _, doc := range everyCorpusDocument(t) {
		answersUnchanged(t, cases, string(doc.raw))
		examined++
		if namesAPerson(string(doc.raw)) {
			naming++
		}
	}
	if examined == 0 || naming == 0 {
		t.Fatalf("%d documents of the corpus examined, %d of them naming a person", examined, naming)
	}
	t.Logf("%d documents of the corpus, %d of them naming a person, answered alike beside refusals naming people", examined, naming)
}

// TestTheStripLeavesAnswersNamingPeopleAsTheyWere draws trust policies
// that name people of the five kinds, as principals and in conditions,
// and holds each answer as TestTheStripLeavesEveryAnswerOfTheCorpusAsItWas
// holds the corpus's.
func TestTheStripLeavesAnswersNamingPeopleAsTheyWere(t *testing.T) {
	cases := callerTable(t)
	d := newDraws()
	examined := 0
	rapid.Check(t, func(t *rapid.T) {
		principal, _, _ := genPerson(t, d)
		condition, _, _ := genPerson(t, d)
		policy, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{
			"Effect": "Allow", "Principal": map[string]any{"AWS": principal}, "Action": "sts:AssumeRole",
			"Condition": map[string]any{"ArnLike": map[string]any{"aws:PrincipalArn": condition}},
		}}})
		if err != nil {
			t.Fatal(err)
		}
		answersUnchanged(t, cases, string(policy))
		examined++
	})
	for _, kind := range personARNKinds {
		if d.persons[kind] == 0 {
			t.Fatalf("over %d policies no %s was strippedDraws (%v)", examined, kind, d.persons)
		}
	}
	t.Logf("%d policies naming people, by kind %v", examined, d.persons)
}

// TestNothingButARefusalsMessagePassesThroughTheStrip: a bundle's other
// text is the account's, or the collector's, and is read as written, a
// person's ARN in it included: the alias, the collector's name, a limit,
// a role's ARN, name and path, and its trust policy.
func TestNothingButARefusalsMessagePassesThroughTheStrip(t *testing.T) {
	const (
		person = "arn:aws:iam::123456789012:user/Jane"
		path   = "/" + person + "/"
		arn    = "arn:aws:iam::123456789012:role" + path + "Jane"
	)
	alias, collector := person, "cloudarq-collect 0.2.0 for "+person
	limit := "the trust policy of " + arn + " was not percent-encoded as IAM sends it, so it is kept as it arrived"
	raw, err := json.Marshal(map[string]any{
		"format": "cloudarq.collect/v1", "provider": "aws", "account": bundleAccount, "partition": "aws", "alias": alias,
		"collected_at": "2026-09-27T00:00:00Z", "collector": collector,
		"pages": []any{map[string]any{"IsTruncated": false, "Roles": []any{map[string]any{
			"Path": path, "RoleName": "Jane", "RoleId": "AROAJANE", "Arn": arn,
			"CreateDate": "2024-01-02T03:04:05Z", "AssumeRolePolicyDocument": janeTrust,
		}}}},
		"refused": []any{map[string]any{"call": "iam:ListAccountAliases", "code": "AccessDenied",
			"message": "User: " + person + " is not authorized to perform: iam:ListAccountAliases"}},
		"limits": []any{limit},
	})
	if err != nil {
		t.Fatal(err)
	}
	f := findingsOf(t, raw, "")
	if f.Error != "" || len(f.Roles) != 1 {
		t.Fatalf("the bundle is not read: %s", f.Error)
	}
	role := f.Roles[0]
	if role.Arn != arn || role.Name != "Jane" || role.Path == nil || *role.Path != path || role.DocumentSHA256 != hexOf([]byte(janeTrust)) {
		t.Errorf("the role reads %s, %s, %v, %s", role.Arn, role.Name, role.Path, role.DocumentSHA256)
	}
	if f.Alias == nil || *f.Alias != alias || f.Collector == nil || *f.Collector != collector || !slices.Equal(f.Limits, []string{limit}) {
		t.Errorf("alias %v, collector %v, limits %+q", f.Alias, f.Collector, f.Limits)
	}
	want := []BundleRefusal{{Call: "iam:ListAccountAliases", Code: "AccessDenied", Message: "User: arn:aws:iam::123456789012:user/(removed) is not authorized to perform: iam:ListAccountAliases"}}
	if !slices.Equal(f.Refused, want) {
		t.Errorf("refused %+v", f.Refused)
	}
}

// The corpus case written before the strip: its refusals, read from the
// bundle itself, are cases of the table.
const personCase = "10-refusal-names-a-person"

// TestTheCorpusCaseOfPeopleIsReadWithoutThem reads the corpus's bundle
// whose refusals name people: each of its refusals is a case of the table
// and is written as that case's want.
func TestTheCorpusCaseOfPeopleIsReadWithoutThem(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(testdata, "bundles", personCase, "bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var written struct {
		Refused []BundleRefusal `json:"refused"`
	}
	if err := json.Unmarshal(raw, &written); err != nil {
		t.Fatal(err)
	}
	cases := callerTable(t)
	f := findingsOf(t, raw, "")
	if len(written.Refused) == 0 || len(f.Refused) != len(written.Refused) {
		t.Fatalf("%d refusals in the bundle, %d in the findings", len(written.Refused), len(f.Refused))
	}
	for i, r := range written.Refused {
		at := slices.IndexFunc(cases, func(c callerCase) bool { return c.Message == r.Message })
		if at < 0 {
			t.Errorf("refusal %d is no case of the table: %+q", i, r.Message)
			continue
		}
		if c := cases[at]; f.Refused[i] != (BundleRefusal{Call: r.Call, Code: r.Code, Message: c.Want}) || c.Want == c.Message {
			t.Errorf("refusal %d, case %s, is written %+q; want %+q", i, c.ID, f.Refused[i].Message, c.Want)
		}
	}
}
