package arch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// From v0.4.0 the engine is licensed under the Functional Source License,
// Version 1.1, with the Apache License 2.0 as its future licence
// (FSL-1.1-ALv2). No file of the release tree may say the engine itself is
// under the Apache License 2.0; third-party material keeps its own licence.
// The release tree is, in a git work tree that tracks an allowlist.txt of
// the files it publishes, the files that list matches; in any other git
// work tree, every file git tracks; and in a tree git does not hold, such
// as a release's files checked on their own, every file under the module's
// root.

// The rules a file of the release tree is held to. Each finding names the
// one it breaks, so a fixture is held to the reason it is refused for.
const (
	// LICENSE is not the FSL-1.1-ALv2 text fsl.software publishes with only
	// its notice filled in.
	ruleLicenceText = "licence-text"
	// A package manifest names the Apache License as its own.
	ruleManifest = "manifest"
	// The engine's own words mention the Apache License where no sentence
	// reviewed below says it.
	ruleClaim = "claim"
	// A sentence reviewed below is no longer in its file, so the list
	// would excuse a sentence nobody reads again.
	ruleStale = "stale"
	// THIRD_PARTY_NOTICES names material under the Apache License 2.0 and
	// does not reproduce its text, which the licence requires a
	// redistribution to give: "You must give any other recipients of the
	// Work or Derivative Works a copy of this License".
	ruleNoticeText = "notice-text"
	// A file holds a NUL byte and is not of a binary format, so it is not
	// read as text, and what it says is not known.
	ruleUnread = "unread"
)

// apacheSHA256 is the sha256 of
// https://www.apache.org/licenses/LICENSE-2.0.txt, read 2026-10-06, which
// THIRD_PARTY_NOTICES reproduces under the heading apacheHeading.
const (
	apacheSHA256  = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
	apacheHeading = "Apache License 2.0"
)

// noticeRule is the line above and below each heading of a licence text
// THIRD_PARTY_NOTICES reproduces.
var noticeRule = strings.Repeat("-", 72)

// fslTemplateSHA256 is the sha256 of
// https://fsl.software/FSL-1.1-ALv2.template.md, read 2026-10-06, whose
// notice is the line fslNotice. LICENSE is that text with its notice line
// filled in and nothing else changed.
const (
	fslTemplateSHA256 = "36b6082235c0a2105174927fc57cc6ae9c41f45a08af2bdcaee18a8dace56177"
	fslNotice         = "Copyright ${year} ${licensor name}"
)

// reviewed are the only sentences of the engine's own words that may
// mention the Apache License, by file, each with whitespace collapsed to
// one space: the future licence FSL-1.1-ALv2 grants, the licence the
// releases before v0.4.0 shipped under, the licence contributions are
// accepted under, which is not the engine's, and what this check holds.
// This file, which states the rules and their fixtures, is the one file
// of the engine's own the check does not read (licenceRules).
var reviewed = map[string][]string{
	"README.md": {
		"From v0.4.0, CloudArq is source available under the Functional Source License, Version 1.1, with the Apache License 2.0 as its future licence (FSL-1.1-ALv2); see [LICENSE](LICENSE).",
		"each version becomes available under the Apache License 2.0 on the second anniversary of the day it was made available.",
		"Versions v0.1.0 to v0.3.0 stay under the Apache License 2.0 they were released with.",
		"no file of the repository names the Apache License 2.0 as the engine's own",
	},
	"CHANGELOG.md": {
		"From v0.4.0 the engine is source available under the Functional Source License, Version 1.1, with the Apache License 2.0 as its future licence (FSL-1.1-ALv2): each version becomes available under the Apache License 2.0 on the second anniversary of the day it was made available.",
		"v0.1.0 to v0.3.0 stay under the Apache License 2.0.",
	},
	"Makefile": {
		"names the Apache License 2.0 as the engine's own",
	},
	"CONTRIBUTING.md": {
		"Contributions are accepted under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0): by opening a pull request, you agree that your contribution is licensed under it, as that licence's \"Submission of Contributions\" clause says, and that it is published as part of CloudArq under the licence in [LICENSE](LICENSE).",
	},
}

// thirdPartyLicences are the third parties' licence texts the release
// tree keeps beside their material, which hold the Apache License only as
// their own: the Unicode License v3 of the Unicode Character Database.
var thirdPartyLicences = []string{"internal/parse/casefold/testdata/license.txt"}

// licenceRules is this file.
const licenceRules = "test/arch/licence_test.go"

// licenceFinding is one rule a file breaks, at a line (0 for the file as a
// whole).
type licenceFinding struct {
	path   string
	line   int
	rule   string
	detail string
}

func (f licenceFinding) String() string {
	return fmt.Sprintf("%s:%d: %s: %s", f.path, f.line, f.rule, f.detail)
}

func TestTheEngineIsUnderItsOwnLicence(t *testing.T) {
	root := moduleRoot(t)
	paths, from := releaseTree(t, root)
	files := map[string][]byte{}
	for _, p := range paths {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(p)))
		if err != nil {
			t.Fatalf("%s is in the release tree and could not be read: %v", p, err)
		}
		files[p] = raw
	}
	read, found := checkLicences(files, reviewed, thirdPartyLicences)
	t.Logf("release tree, %s: %d files; %d read as text, %d binary; LICENSE read: %t; %d package manifests; %d third-party licence texts left to their own licence; %s, which states the rules, left unread: %t",
		from, len(paths), read.text, read.binary, read.licence, read.manifests, read.vendored, licenceRules, read.rules)
	if !read.licence {
		t.Error("the release tree has no LICENSE, so the engine's own licence was not read")
	}
	if read.text == 0 {
		t.Error("no file of the release tree was read as text; this test examined nothing")
	}
	for _, f := range found {
		t.Error(f)
	}
}

// releaseTree lists the release tree's files, and says how it found them.
func releaseTree(t *testing.T, root string) (paths []string, from string) {
	t.Helper()
	if !gitTopLevel(root) {
		return walkTree(t, root), "every file under the module's root, which no git work tree holds"
	}
	tracked := gitFiles(t, root)
	var lists []string
	for _, p := range tracked {
		if path.Base(p) == "allowlist.txt" {
			lists = append(lists, p)
		}
	}
	switch len(lists) {
	case 0:
		return tracked, "every file git tracks"
	case 1:
	default:
		t.Fatalf("git tracks %d files named allowlist.txt, %v, so which one lists the release tree is not known", len(lists), lists)
	}
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(lists[0])))
	if err != nil {
		t.Fatal(err)
	}
	var specs []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		specs = append(specs, ":(glob)"+line)
	}
	if len(specs) == 0 {
		t.Fatalf("%s names nothing", lists[0])
	}
	return gitFiles(t, root, specs...), fmt.Sprintf("the files the %d lines of the allowlist git tracks match", len(specs))
}

// gitTopLevel reports whether root is the top of a git work tree.
func gitTopLevel(root string) bool {
	out, err := exec.Command("git", "-C", root, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return false
	}
	top, err1 := filepath.EvalSymlinks(strings.TrimSpace(string(out)))
	here, err2 := filepath.EvalSymlinks(root)
	return err1 == nil && err2 == nil && top == here
}

// gitFiles is every file git tracks under root, or those the pathspecs
// match.
func gitFiles(t *testing.T, root string, specs ...string) []string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", root, "ls-files", "-z", "--"}, specs...)...).Output()
	if err != nil {
		t.Fatalf("git ls-files in %s: %v", root, err)
	}
	var paths []string
	for _, p := range strings.Split(string(out), "\x00") {
		if p != "" {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		t.Fatalf("git ls-files listed no file in %s; this test examined nothing", root)
	}
	sort.Strings(paths)
	return paths
}

// walkTree is every file under root but in .git and node_modules, which no
// release holds.
func walkTree(t *testing.T, root string) []string {
	t.Helper()
	var paths []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		paths = append(paths, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if len(paths) == 0 {
		t.Fatalf("no file under %s; this test examined nothing", root)
	}
	sort.Strings(paths)
	return paths
}

// licenceRead counts what checkLicences read.
type licenceRead struct {
	text, binary, manifests, vendored int
	licence, rules                    bool
}

// apache finds a mention of the Apache License, in any case.
var apache = regexp.MustCompile(`(?i)apache`)

// checkLicences holds the files of a release tree, by path, to the rules.
func checkLicences(files map[string][]byte, reviewed map[string][]string, vendored []string) (read licenceRead, found []licenceFinding) {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		raw := files[p]
		if bytes.IndexByte(raw, 0) >= 0 {
			if binaryFormat.MatchString(path.Base(p)) {
				read.binary++
			} else {
				found = append(found, licenceFinding{p, 0, ruleUnread, "the file holds a NUL byte and its name is not a binary format's, so it is not read as text"})
			}
			continue
		}
		read.text++
		text := string(raw)
		switch base := path.Base(p); {
		case p == "LICENSE":
			read.licence = true
			found = append(found, checkLicenceText(text)...)
			continue
		case p == "NOTICE":
			found = append(found, checkNoticeHolder(text)...)
		case p == licenceRules:
			read.rules = true
			continue
		case slices.Contains(vendored, p):
			read.vendored++
			continue
		case base == "package.json":
			// A manifest that names Apache as its licence is refused once,
			// for that; any other mention is a claim like any other.
			read.manifests++
			if f := checkManifest(p, raw); len(f) > 0 {
				found = append(found, f...)
				continue
			}
		case p == "THIRD_PARTY_NOTICES":
			// Ours is what comes before the first numbered entry; each
			// entry, and the licence texts after the list, are third
			// parties'.
			found = append(found, checkNoticeTexts(text)...)
			if at := regexp.MustCompile(`(?m)^1\. `).FindStringIndex(text); at != nil {
				text = text[:at[0]]
			}
		}
		found = append(found, checkClaims(p, text, reviewed[p])...)
	}
	for _, p := range sortedKeys(reviewed) {
		if _, ok := files[p]; !ok {
			found = append(found, licenceFinding{p, 0, ruleStale, "the file is not in the release tree, and sentences are reviewed for it"})
		}
	}
	for _, p := range vendored {
		if _, ok := files[p]; !ok {
			found = append(found, licenceFinding{p, 0, ruleStale, "the file is not in the release tree, and it is listed as a third party's licence text"})
		}
	}
	return read, found
}

// binaryFormat is the name of a file of a format that is not text, which a
// NUL byte does not make suspect: WebAssembly, images, fonts, archives and
// PDF.
var binaryFormat = regexp.MustCompile(`(?i)\.(wasm|png|jpe?g|gif|ico|webp|avif|woff2?|gz|zip|pdf)$`)

// licensorNotice is the notice LICENSE fills the template's with: the
// year, or years, and the licensor, and nothing else.
var licensorNotice = regexp.MustCompile(`^Copyright 20[0-9]{2}(-20[0-9]{2})? Abdallah Khaldi, trading as CloudArq$`)

// checkNoticeHolder holds NOTICE's first copyright line to LICENSE's
// licensor, so that the two files name one holder.
func checkNoticeHolder(text string) []licenceFinding {
	for i, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, "Copyright ") {
			continue
		}
		if !licensorNotice.MatchString(line) {
			return []licenceFinding{{"NOTICE", i + 1, ruleLicenceText, fmt.Sprintf("NOTICE's copyright line is %q, not LICENSE's licensor's", line)}}
		}
		return nil
	}
	return []licenceFinding{{"NOTICE", 0, ruleLicenceText, "NOTICE has no copyright line naming LICENSE's licensor"}}
}

// checkLicenceText holds LICENSE to the FSL-1.1-ALv2 template: the line
// after "## Notice" is the licensor's notice, and with that line put back
// as the template writes it, its sha256 is the template's.
func checkLicenceText(text string) []licenceFinding {
	if strings.Contains(text, "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION") {
		return []licenceFinding{{"LICENSE", 1, ruleLicenceText, "LICENSE is the Apache License 2.0's text, not FSL-1.1-ALv2"}}
	}
	notice := regexp.MustCompile(`(?m)^## Notice\n\n(Copyright [^\n]+)\n`)
	at := notice.FindStringSubmatchIndex(text)
	if at == nil {
		return []licenceFinding{{"LICENSE", 0, ruleLicenceText, "LICENSE has no \"## Notice\" heading followed by one Copyright line, as FSL-1.1-ALv2 writes it"}}
	}
	if strings.Contains(text[at[3]:], "\n## Notice\n") {
		return []licenceFinding{{"LICENSE", 0, ruleLicenceText, "LICENSE has more than one \"## Notice\" heading"}}
	}
	if got := text[at[2]:at[3]]; !licensorNotice.MatchString(got) {
		line := strings.Count(text[:at[2]], "\n") + 1
		return []licenceFinding{{"LICENSE", line, ruleLicenceText, fmt.Sprintf("the notice is %q, not the licensor's, as %q", got, "Copyright 2026 Abdallah Khaldi, trading as CloudArq")}}
	}
	template := text[:at[2]] + fslNotice + text[at[3]:]
	sum := sha256.Sum256([]byte(template))
	if got := hex.EncodeToString(sum[:]); got != fslTemplateSHA256 {
		line := strings.Count(text[:at[2]], "\n") + 1
		return []licenceFinding{{"LICENSE", 0, ruleLicenceText, fmt.Sprintf("with line %d's notice put back as %q, LICENSE's sha256 is %s, not FSL-1.1-ALv2's, %s", line, fslNotice, got, fslTemplateSHA256)}}
	}
	return nil
}

// checkNoticeTexts holds THIRD_PARTY_NOTICES, whose list names material
// under the Apache License 2.0, to reproducing that licence: a block
// headed apacheHeading between two rule lines, whose text, from the blank
// line after them to the next block or the end, is apache.org's byte for
// byte. The list is what comes between the first numbered entry and the
// first rule line.
func checkNoticeTexts(text string) []licenceFinding {
	list := text
	if at := regexp.MustCompile(`(?m)^1\. `).FindStringIndex(list); at != nil {
		list = list[at[0]:]
	}
	if at := strings.Index(list, "\n"+noticeRule+"\n"); at >= 0 {
		list = list[:at]
	}
	flat, _ := collapse(list)
	if !strings.Contains(flat, apacheHeading) {
		return nil
	}
	heading := regexp.MustCompile(`(?m)^` + noticeRule + `\n` + regexp.QuoteMeta(apacheHeading) + `\n(?:[^\n]+\n)*?` + noticeRule + `\n\n`)
	at := heading.FindStringIndex(text)
	if at == nil {
		return []licenceFinding{{"THIRD_PARTY_NOTICES", 0, ruleNoticeText, fmt.Sprintf("the list names the %s, and no block headed %q reproduces its text", apacheHeading, apacheHeading)}}
	}
	body := text[at[1]:]
	if end := strings.Index(body, "\n\n\n"+noticeRule+"\n"); end >= 0 {
		body = body[:end+1]
	}
	sum := sha256.Sum256([]byte(body))
	if got := hex.EncodeToString(sum[:]); got != apacheSHA256 {
		line := strings.Count(text[:at[0]], "\n") + 2
		return []licenceFinding{{"THIRD_PARTY_NOTICES", line, ruleNoticeText, fmt.Sprintf("the text under %q has sha256 %s, not apache.org's, %s", apacheHeading, got, apacheSHA256)}}
	}
	return nil
}

// checkManifest refuses a package manifest whose license, or any entry of
// its licenses, names the Apache License.
func checkManifest(p string, raw []byte) []licenceFinding {
	var m struct {
		License  json.RawMessage `json:"license"`
		Licenses json.RawMessage `json:"licenses"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return []licenceFinding{{p, 0, ruleManifest, fmt.Sprintf("not read as a package manifest: %v", err)}}
	}
	var found []licenceFinding
	for _, field := range []struct {
		name  string
		value json.RawMessage
	}{{"license", m.License}, {"licenses", m.Licenses}} {
		if loc := apache.FindIndex(field.value); loc != nil {
			found = append(found, licenceFinding{p, lineOfField(raw, field.name), ruleManifest, fmt.Sprintf("%s is %s, the Apache License, as the package's own", field.name, field.value)})
		}
	}
	return found
}

// lineOfField is the line a manifest's top-level field is written on, or 0.
func lineOfField(raw []byte, name string) int {
	at := bytes.Index(raw, []byte(`"`+name+`"`))
	if at < 0 {
		return 0
	}
	return bytes.Count(raw[:at], []byte("\n")) + 1
}

// checkClaims finds every mention of the Apache License in text, the
// engine's own words in p, that no reviewed sentence holds, and every
// reviewed sentence that is not in text. Whitespace is collapsed first, so
// a sentence holds wherever its lines are wrapped.
func checkClaims(p, text string, sentences []string) []licenceFinding {
	flat, lines := collapse(text)
	covered := make([]bool, len(flat))
	var found []licenceFinding
	for _, s := range sentences {
		n := 0
		for from := 0; ; {
			at := strings.Index(flat[from:], s)
			if at < 0 {
				break
			}
			for i := from + at; i < from+at+len(s); i++ {
				covered[i] = true
			}
			n++
			from += at + len(s)
		}
		if n == 0 {
			found = append(found, licenceFinding{p, 0, ruleStale, fmt.Sprintf("the reviewed sentence %q is not in the file", s)})
		}
	}
	for _, loc := range apache.FindAllStringIndex(flat, -1) {
		if covered[loc[0]] {
			continue
		}
		found = append(found, licenceFinding{p, lines[loc[0]], ruleClaim, fmt.Sprintf("%q mentions the Apache License, and no reviewed sentence says it", around(flat, loc[0]))})
	}
	return found
}

// collapse writes text with each run of whitespace as one space, and the
// line of the original that each byte of the result comes from.
func collapse(text string) (string, []int) {
	var b strings.Builder
	var lines []int
	line, space := 1, false
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			if c == '\n' {
				line++
			}
			if !space && b.Len() > 0 {
				space = true
				b.WriteByte(' ')
				lines = append(lines, line)
			}
			continue
		}
		space = false
		b.WriteByte(c)
		lines = append(lines, line)
	}
	return b.String(), lines
}

// around is the words either side of a mention, for a finding.
func around(flat string, at int) string {
	from, to := max(0, at-60), min(len(flat), at+60)
	return flat[from:to]
}

// TestEachLicenceClaimIsRefusedForItsOwnReason holds each rule to a tree
// that breaks it and to one that does not.
func TestEachLicenceClaimIsRefusedForItsOwnReason(t *testing.T) {
	fsl := strings.Replace(fslTemplateForTest(t), fslNotice, "Copyright 2026 Abdallah Khaldi, trading as CloudArq", 1)
	notices := "THIRD-PARTY NOTICES\n\nCloudArq is licensed under FSL-1.1-ALv2 (LICENSE).\n\n" +
		"1. A module\n\n   example.com/module: Apache License 2.0.\n\n\n" +
		noticeRule + "\n" + apacheHeading + "\n(example.com/module)\n" + noticeRule + "\n\n" + apacheTextForTest(t)
	review := map[string][]string{
		"README.md": {"Releases before v0.4.0 stay under the Apache License 2.0."},
		"NOTICE":    {"This product includes a thing, used under the Apache License 2.0."},
	}
	vendored := []string{"vendor/thing/LICENSE.txt"}
	readme := "# CloudArq\n\nSource available under FSL-1.1-ALv2.\nReleases before v0.4.0 stay under\nthe Apache License 2.0.\n"
	base := func() map[string][]byte {
		return map[string][]byte{
			"LICENSE":                  []byte(fsl),
			"README.md":                []byte(readme),
			"NOTICE":                   []byte("CloudArq\nCopyright 2026 Abdallah Khaldi, trading as CloudArq\n\nThis product includes a thing, used under the\nApache License 2.0.\n"),
			"THIRD_PARTY_NOTICES":      []byte(notices),
			"vendor/thing/LICENSE.txt": []byte("Apache License\nVersion 2.0, January 2004\n"),
			"web/engine/package.json":  []byte(`{"name": "engine", "license": "FSL-1.1-ALv2"}`),
			"cloudarq.wasm":            {0, 'a', 's', 'm', 'A', 'p', 'a', 'c', 'h', 'e'},
		}
	}
	read, found := checkLicences(base(), review, vendored)
	if len(found) != 0 {
		t.Fatalf("a tree that breaks no rule was refused:\n%s", licenceFindings(found))
	}
	if !read.licence || read.text != 6 || read.binary != 1 || read.manifests != 1 || read.vendored != 1 {
		t.Fatalf("the clean tree was read as %+v", read)
	}
	// md is joined to the markdown fixtures' names when the test runs, so
	// this file names no markdown document the release does not publish.
	const md = ".md"
	for _, c := range []struct {
		name   string
		change func(map[string][]byte)
		rule   string
		line   int
	}{
		{"LICENSE is Apache's text", func(f map[string][]byte) {
			f["LICENSE"] = []byte("                                 Apache License\n   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION\n")
		}, ruleLicenceText, 1},
		{"LICENSE is FSL with a permitted purpose changed", func(f map[string][]byte) {
			f["LICENSE"] = []byte(strings.Replace(fsl, "for your internal use and access", "for any use", 1))
		}, ruleLicenceText, 0},
		{"LICENSE is FSL with no notice", func(f map[string][]byte) {
			f["LICENSE"] = []byte(strings.Replace(fsl, "## Notice\n\nCopyright 2026 Abdallah Khaldi, trading as CloudArq\n", "", 1))
		}, ruleLicenceText, 0},
		{"LICENSE's notice is the template's, unfilled", func(f map[string][]byte) {
			f["LICENSE"] = []byte(strings.Replace(fsl, "Copyright 2026 Abdallah Khaldi, trading as CloudArq", fslNotice, 1))
		}, ruleLicenceText, 9},
		{"LICENSE's notice names another licensor", func(f map[string][]byte) {
			f["LICENSE"] = []byte(strings.Replace(fsl, "Copyright 2026 Abdallah Khaldi, trading as CloudArq", "Copyright 1999 Someone Else", 1))
		}, ruleLicenceText, 9},
		{"LICENSE's notice gives the engine Apache", func(f map[string][]byte) {
			f["LICENSE"] = []byte(strings.Replace(fsl, "Copyright 2026 Abdallah Khaldi, trading as CloudArq", "Copyright 2026 Abdallah Khaldi, trading as CloudArq. Licensed under the Apache License 2.0.", 1))
		}, ruleLicenceText, 9},
		{"LICENSE is FSL-1.1-MIT", func(f map[string][]byte) {
			f["LICENSE"] = []byte(strings.Replace(fsl, "FSL-1.1-ALv2", "FSL-1.1-MIT", 1))
		}, ruleLicenceText, 0},
		{"a manifest's license is Apache-2.0", func(f map[string][]byte) {
			f["web/engine/package.json"] = []byte("{\n  \"name\": \"engine\",\n  \"license\": \"Apache-2.0\"\n}\n")
		}, ruleManifest, 3},
		{"a manifest's licenses name Apache", func(f map[string][]byte) {
			f["web/engine/package.json"] = []byte(`{"licenses": [{"type": "Apache-2.0"}]}`)
		}, ruleManifest, 1},
		{"README says the engine is under Apache", func(f map[string][]byte) {
			f["README.md"] = []byte(readme + "\n## Licence\n\nApache License 2.0; see [LICENSE](LICENSE).\n")
		}, ruleClaim, 9},
		{"a Go comment says the engine is under Apache", func(f map[string][]byte) {
			f["internal/eval/doc.go"] = []byte("// Package eval is licensed under the\n// Apache License 2.0.\npackage eval\n")
		}, ruleClaim, 2},
		{"the notices' preamble says the engine is under Apache", func(f map[string][]byte) {
			f["THIRD_PARTY_NOTICES"] = []byte(strings.Replace(notices, "under FSL-1.1-ALv2 (LICENSE)", "under the Apache License 2.0 (LICENSE)", 1))
		}, ruleClaim, 3},
		{"NOTICE says the engine is under Apache", func(f map[string][]byte) {
			f["NOTICE"] = []byte(strings.Replace(string(f["NOTICE"]), "trading as CloudArq\n", "trading as CloudArq\nLicensed under the Apache License 2.0.\n", 1))
		}, ruleClaim, 3},
		{"the notices name Apache 2.0 and do not reproduce it", func(f map[string][]byte) {
			f["THIRD_PARTY_NOTICES"] = []byte("THIRD-PARTY NOTICES\n\nCloudArq is licensed under FSL-1.1-ALv2 (LICENSE).\n\n1. A module\n\n   example.com/module: Apache License 2.0.\n")
		}, ruleNoticeText, 0},
		{"the notices' Apache text is changed", func(f map[string][]byte) {
			f["THIRD_PARTY_NOTICES"] = []byte(strings.Replace(notices, "You must give any other recipients", "You may give any other recipients", 1))
		}, ruleNoticeText, 11},
		{"the notices' Apache text is cut short by another block", func(f map[string][]byte) {
			f["THIRD_PARTY_NOTICES"] = []byte(strings.Replace(notices, "   END OF TERMS AND CONDITIONS\n", "\n\n"+noticeRule+"\nMIT License\n"+noticeRule+"\n\n", 1))
		}, ruleNoticeText, 11},
		{"NOTICE names a holder other than LICENSE's licensor", func(f map[string][]byte) {
			f["NOTICE"] = []byte(strings.Replace(string(f["NOTICE"]), ", trading as CloudArq", "", 1))
		}, ruleLicenceText, 2},
		{"NOTICE names no holder", func(f map[string][]byte) {
			f["NOTICE"] = []byte("CloudArq\n\nThis product includes a thing, used under the\nApache License 2.0.\n")
		}, ruleLicenceText, 0},
		{"NOTICE includes the engine under Apache", func(f map[string][]byte) {
			f["NOTICE"] = append(f["NOTICE"], "\nThis product includes CloudArq's engine, licensed under the\nApache License 2.0.\n"...)
		}, ruleClaim, 8},
		{"a LICENSE below the root gives a package Apache", func(f map[string][]byte) {
			f["web/engine/LICENSE"] = []byte("Apache License\nVersion 2.0, January 2004\n")
		}, ruleClaim, 1},
		{"a markdown LICENSE below the root gives a package Apache", func(f map[string][]byte) {
			f["internal/report/LICENSE"+md] = []byte("This package is licensed under the\nApache License 2.0.\n")
		}, ruleClaim, 2},
		{"a third-party licence listed is gone", func(f map[string][]byte) {
			delete(f, "vendor/thing/LICENSE.txt")
		}, ruleStale, 0},
		{"a text file holds a NUL byte", func(f map[string][]byte) {
			f["docs/licence"+md] = []byte("The engine is under the Apache License 2.0.\x00\n")
		}, ruleUnread, 0},
		{"a reviewed sentence is gone", func(f map[string][]byte) {
			f["README.md"] = []byte("# CloudArq\n\nSource available under FSL-1.1-ALv2.\n")
		}, ruleStale, 0},
		{"a reviewed file is gone", func(f map[string][]byte) {
			delete(f, "README.md")
		}, ruleStale, 0},
		{"a source file named like a licence", func(f map[string][]byte) {
			f["internal/report/license.go"] = []byte("package report\n\n// The engine is under the Apache License 2.0.\n")
		}, ruleClaim, 3},
		{"a licence named like a vendored one at the root", func(f map[string][]byte) {
			f["LICENSE.txt"] = []byte("Apache License\nVersion 2.0, January 2004\n")
		}, ruleClaim, 1},
	} {
		files := base()
		c.change(files)
		_, found := checkLicences(files, review, vendored)
		if len(found) != 1 || found[0].rule != c.rule || found[0].line != c.line {
			t.Errorf("%s: want one %s finding at line %d, got:\n%s", c.name, c.rule, c.line, licenceFindings(found))
		}
	}
}

// fslTemplateForTest is LICENSE with its notice put back, which the
// release tree's own check holds to the template's digest.
func fslTemplateForTest(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(moduleRoot(t), "LICENSE"))
	if err != nil {
		t.Fatal(err)
	}
	text := regexp.MustCompile(`(?m)^Copyright [^\n]+$`).ReplaceAllLiteralString(string(raw), fslNotice)
	sum := sha256.Sum256([]byte(text))
	if hex.EncodeToString(sum[:]) != fslTemplateSHA256 {
		t.Fatalf("LICENSE, with its notice put back, is not FSL-1.1-ALv2's template, so the fixtures have no licence to start from")
	}
	return text
}

// apacheTextForTest is the Apache License 2.0 as THIRD_PARTY_NOTICES
// reproduces it, held to apache.org's digest.
func apacheTextForTest(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(moduleRoot(t), "THIRD_PARTY_NOTICES"))
	if err != nil {
		t.Fatal(err)
	}
	head := "\n" + noticeRule + "\n" + apacheHeading + "\n"
	from := strings.Index(string(raw), head)
	if from < 0 {
		t.Fatalf("THIRD_PARTY_NOTICES has no block headed %q, so the fixtures have no Apache text to start from", apacheHeading)
	}
	rest := string(raw[from+len(head):])
	at := strings.Index(rest, "\n"+noticeRule+"\n\n")
	if at < 0 {
		t.Fatalf("the block headed %q in THIRD_PARTY_NOTICES has no rule line below its heading", apacheHeading)
	}
	text := rest[at+len(noticeRule)+3:]
	if end := strings.Index(text, "\n\n\n"+noticeRule+"\n"); end >= 0 {
		text = text[:end+1]
	}
	sum := sha256.Sum256([]byte(text))
	if hex.EncodeToString(sum[:]) != apacheSHA256 {
		t.Fatalf("THIRD_PARTY_NOTICES's Apache License 2.0 is not apache.org's text, so the fixtures have no Apache text to start from")
	}
	return text
}

func licenceFindings(found []licenceFinding) string {
	if len(found) == 0 {
		return "  (none)"
	}
	var b strings.Builder
	for _, f := range found {
		b.WriteString("  " + f.String() + "\n")
	}
	return b.String()
}
