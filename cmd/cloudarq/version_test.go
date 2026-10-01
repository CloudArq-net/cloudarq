package main

import (
	"debug/buildinfo"
	"testing"
)

// TestVersionIsTheOneGoRecorded runs the built command and reads the build
// information Go wrote into the same binary. `go install …@v0.1.0` records
// v0.1.0 there, and a build inside a git checkout records the pseudo-version
// of its commit; either is what the command prints, without the leading v.
// 0.0.0-dev is printed only when Go recorded no version at all.
func TestVersionIsTheOneGoRecorded(t *testing.T) {
	info, err := buildinfo.ReadFile(binary)
	if err != nil {
		t.Fatalf("read the build information of the command under test: %v", err)
	}
	want := "0.0.0-dev"
	if recorded := info.Main.Version; recorded != "" && recorded != "(devel)" {
		want = recorded[1:]
	}
	got := invocation{args: []string{"version"}}.run(t)
	if got.code != 0 || got.stdout != "cloudarq "+want+"\n" || got.stderr != "" {
		t.Errorf("the binary records %q\n  version: exit %d, stdout %q, stderr %q\n  want exit 0, stdout %q",
			info.Main.Version, got.code, got.stdout, got.stderr, "cloudarq "+want+"\n")
	}
	t.Logf("the binary records %q and prints %q", info.Main.Version, got.stdout)
}

// TestVersionOf holds the one release build the test above cannot make: a
// tagged module version, as `go install` records it.
func TestVersionOf(t *testing.T) {
	for recorded, want := range map[string]string{
		"v0.1.0":                             "0.1.0",
		"v0.0.0-20260927005003-08dd70e62f9c": "0.0.0-20260927005003-08dd70e62f9c",
		"v0.1.1-0.20260927131400-08dd70e62f9c+dirty": "0.1.1-0.20260927131400-08dd70e62f9c+dirty",
		"(devel)": "0.0.0-dev",
		"":        "0.0.0-dev",
	} {
		if got := versionOf(recorded); got != want {
			t.Errorf("versionOf(%q) = %q, want %q", recorded, got, want)
		}
	}
}
