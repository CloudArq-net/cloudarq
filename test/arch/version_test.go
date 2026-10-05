package arch

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// versionScript is the one place the engine's version is worked out from
// git: the release workflow and the WebAssembly build both ask it, so a
// file of a release and the findings the engine writes name one version.
const versionScript = "scripts/version.sh"

// TestTheVersionIsTheReleaseTagGitDescribes runs scripts/version.sh in
// repositories built for the purpose, each holding a copy of the script, and
// reads what it prints. Only a tag written as a release's, v and a digit,
// names a version: a later tag of any other kind, such as a backup taken
// before rewriting history, must not take the name, and neither may a tag
// that merely begins with v, such as vendor-x. With no release tag the
// version is the commit's hash; a tree with changes to tracked files adds
// -dirty; outside git it is 0.0.0-dev.
func TestTheVersionIsTheReleaseTagGitDescribes(t *testing.T) {
	script := readVersionScript(t)

	t.Run("a release tag on the commit is the version, without its v", func(t *testing.T) {
		r := newVersionRepo(t, script)
		r.commit("one")
		r.git("tag", "-a", "-m", "v0.3.0", "v0.3.0")
		r.expect(t, "0.3.0")
	})

	for _, kind := range []string{"lightweight", "annotated"} {
		t.Run("a later backup/x tag, "+kind+", leaves v0.3.0 the version", func(t *testing.T) {
			r := newVersionRepo(t, script)
			r.commit("one")
			r.git("tag", "-a", "-m", "v0.3.0", "v0.3.0")
			r.commit("two")
			r.tag(kind, "backup/x")
			r.expectPattern(t, `^0\.3\.0-1-g([0-9a-f]{7,40})$`)
		})

		t.Run("a vendor-x tag alone, "+kind+", leaves the hash the version", func(t *testing.T) {
			r := newVersionRepo(t, script)
			r.commit("one")
			r.tag(kind, "vendor-x")
			r.expectPattern(t, `^([0-9a-f]{7,40})$`)
		})
	}

	t.Run("no tag leaves the hash the version", func(t *testing.T) {
		r := newVersionRepo(t, script)
		r.commit("one")
		r.expectPattern(t, `^([0-9a-f]{7,40})$`)
	})

	t.Run("a change to a tracked file adds -dirty to the hash", func(t *testing.T) {
		r := newVersionRepo(t, script)
		r.commit("one")
		r.write("README", "changed\n")
		r.expectPattern(t, `^([0-9a-f]{7,40})-dirty$`)
	})

	t.Run("a change to a tracked file adds -dirty to the release tag", func(t *testing.T) {
		r := newVersionRepo(t, script)
		r.commit("one")
		r.git("tag", "-a", "-m", "v0.3.0", "v0.3.0")
		r.write("README", "changed\n")
		r.expect(t, "0.3.0-dirty")
	})

	t.Run("outside git the version is 0.0.0-dev", func(t *testing.T) {
		r := newVersionDir(t, script)
		r.expect(t, "0.0.0-dev")
	})
}

// TestOnlyTheVersionScriptAsksGitForTheVersion: no shell script, Makefile
// or workflow but scripts/version.sh runs git describe, so nothing that
// builds the engine can name it by a rule of its own.
func TestOnlyTheVersionScriptAsksGitForTheVersion(t *testing.T) {
	root := moduleRoot(t)
	describe := regexp.MustCompile(`\bgit\s+(?:-\S+\s+)*describe\b`)
	examined, found := 0, false
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		name := d.Name()
		isWorkflow := strings.HasPrefix(rel, ".github/workflows/") && (strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml"))
		if !(strings.HasSuffix(name, ".sh") || name == "Makefile" || strings.HasSuffix(name, ".mk") || isWorkflow) {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		examined++
		if rel == versionScript {
			if !describe.Match(raw) {
				t.Errorf("%s does not run git describe, yet it is the one place the version is worked out", rel)
			}
			found = true
			return nil
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			if describe.MatchString(line) {
				t.Errorf("%s:%d runs git describe itself; the version is %s's to give: %s", rel, i+1, versionScript, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Errorf("%s was not found under %s", versionScript, root)
	}
	if examined < 2 {
		t.Fatalf("examined %d shell scripts, Makefiles and workflows; this test examined too little to hold anything", examined)
	}
	t.Logf("examined %d shell scripts, Makefiles and workflows", examined)
}

// readVersionScript is scripts/version.sh's text and mode. The release
// workflow runs it as a command, so it must be executable.
func readVersionScript(t *testing.T) versionScriptFile {
	t.Helper()
	path := filepath.Join(moduleRoot(t), filepath.FromSlash(versionScript))
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("%s is not executable (%v); the release workflow runs it as a command", versionScript, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return versionScriptFile{text: raw, mode: info.Mode().Perm()}
}

type versionScriptFile struct {
	text []byte
	mode fs.FileMode
}

// versionRepo is a directory holding a copy of scripts/version.sh, with git
// run in it under an environment that reads no configuration of the
// machine's or the user's and never looks above the directory for a
// repository.
type versionRepo struct {
	t   *testing.T
	dir string
	env []string
	n   int
}

func newVersionDir(t *testing.T, script versionScriptFile) *versionRepo {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"LC_ALL=C",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_CEILING_DIRECTORIES=" + filepath.Dir(dir),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=Version Test",
		"GIT_AUTHOR_EMAIL=version@example.com",
		"GIT_COMMITTER_NAME=Version Test",
		"GIT_COMMITTER_EMAIL=version@example.com",
	}
	if tmp := os.Getenv("TMPDIR"); tmp != "" {
		env = append(env, "TMPDIR="+tmp)
	}
	r := &versionRepo{t: t, dir: dir, env: env}
	if err := os.MkdirAll(filepath.Join(dir, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(versionScript)), script.text, script.mode); err != nil {
		t.Fatal(err)
	}
	return r
}

func newVersionRepo(t *testing.T, script versionScriptFile) *versionRepo {
	t.Helper()
	r := newVersionDir(t, script)
	r.git("-c", "init.defaultBranch=main", "init", "-q")
	r.write("README", "a repository for the version test\n")
	return r
}

func (r *versionRepo) write(name, text string) {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(r.dir, name), []byte(text), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

// commit commits everything in the directory, the script included, with a
// date a second after the last, so each commit is distinct.
func (r *versionRepo) commit(message string) {
	r.t.Helper()
	r.n++
	r.write("README", "a repository for the version test\n"+message+"\n")
	r.git("add", "-A")
	date := time.Date(2026, 1, 1, 0, 0, r.n, 0, time.UTC).Format(time.RFC3339)
	r.gitEnv([]string{"GIT_AUTHOR_DATE=" + date, "GIT_COMMITTER_DATE=" + date}, "commit", "-q", "--no-gpg-sign", "-m", message)
}

func (r *versionRepo) tag(kind, name string) {
	r.t.Helper()
	switch kind {
	case "lightweight":
		r.git("tag", name)
	case "annotated":
		r.git("tag", "-a", "-m", name, name)
	default:
		r.t.Fatalf("no tag of kind %q", kind)
	}
}

func (r *versionRepo) git(args ...string) string {
	r.t.Helper()
	return r.gitEnv(nil, args...)
}

func (r *versionRepo) gitEnv(extra []string, args ...string) string {
	r.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = r.dir
	cmd.Env = append(append([]string{}, r.env...), extra...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// version runs the copy of scripts/version.sh from the directory's root,
// as the release workflow runs it from the repository's, and returns what
// it printed, which must be one line.
func (r *versionRepo) version(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(r.dir, filepath.FromSlash(versionScript)))
	cmd.Dir = r.dir
	cmd.Env = r.env
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s: %v\nstdout: %q\nstderr: %s", versionScript, err, out, stderr.String())
	}
	s := string(out)
	if !strings.HasSuffix(s, "\n") || strings.Count(s, "\n") != 1 {
		t.Fatalf("%s printed %q, not one line", versionScript, s)
	}
	return strings.TrimSuffix(s, "\n")
}

func (r *versionRepo) expect(t *testing.T, want string) {
	t.Helper()
	if got := r.version(t); got != want {
		t.Errorf("%s printed %q, want %q", versionScript, got, want)
	}
}

// expectPattern holds the version to a pattern whose one group is a hash,
// which must abbreviate the commit checked out.
func (r *versionRepo) expectPattern(t *testing.T, pattern string) {
	t.Helper()
	got := r.version(t)
	m := regexp.MustCompile(pattern).FindStringSubmatch(got)
	if m == nil {
		t.Errorf("%s printed %q, want a match for %s", versionScript, got, pattern)
		return
	}
	head := r.git("rev-parse", "HEAD")
	if !strings.HasPrefix(head, m[1]) {
		t.Errorf("%s printed %q, whose hash %s does not abbreviate HEAD %s", versionScript, got, m[1], head)
	}
}
