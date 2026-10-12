package gitrepo

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseInputs(t *testing.T) {
	in, err := ParseInputs(map[string]any{
		"repository": " https://github.com/acme/web ",
		"ref":        "main",
		"token":      "tok",
	})
	if err != nil {
		t.Fatal(err)
	}
	if in.Repository != "https://github.com/acme/web" || in.Ref != "main" {
		t.Fatalf("unexpected inputs: %+v", in)
	}
	if in.Username != "x-access-token" {
		t.Fatalf("token without username should default the user, got %q", in.Username)
	}
}

func TestParseInputsRejectsUnsafeValues(t *testing.T) {
	cases := map[string]map[string]any{
		"missing repository": {},
		"file url":           {"repository": "file:///etc"},
		"ssh url":            {"repository": "ssh://git@github.com/acme/web"},
		"http url":           {"repository": "http://github.com/acme/web"},
		"embedded creds":     {"repository": "https://user:pass@github.com/acme/web"},
		"option-like ref":    {"repository": "https://github.com/acme/web", "ref": "--upload-pack=x"},
	}
	for name, inputs := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseInputs(inputs); err == nil {
				t.Fatalf("expected an error for %v", inputs)
			}
		})
	}
}

func TestRedactURL(t *testing.T) {
	if got := redactURL("https://user:secret@github.com/acme/web"); strings.Contains(got, "secret") {
		t.Fatalf("credentials leaked: %s", got)
	}
}

// TestCloneLocalRepository clones a local repository end to end. ParseInputs
// only admits https, so Clone is driven directly with a path to exercise the
// git plumbing without network access.
func TestCloneLocalRepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	src := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = src
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "--quiet", "--initial-branch=main")
	if err := os.WriteFile(filepath.Join(src, "app.env"), []byte("KEY=value\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "--quiet", "-m", "init")

	checkout, err := Clone(context.Background(), Inputs{Repository: src, Ref: "main"}, Options{TempDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(checkout.Dir, "app.env")); err != nil {
		t.Fatalf("file missing from checkout: %v", err)
	}
	if len(checkout.Commit) < 40 {
		t.Fatalf("expected a commit SHA, got %q", checkout.Commit)
	}
	if err := checkout.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(checkout.Dir); !os.IsNotExist(err) {
		t.Fatalf("checkout dir not removed: %v", err)
	}
}

func TestCloneFailureRedactsToken(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	_, err := Clone(context.Background(), Inputs{
		Repository: filepath.Join(t.TempDir(), "missing"),
		Username:   "u",
		Token:      "super-secret-token",
	}, Options{TempDir: t.TempDir()})
	if err == nil {
		t.Fatal("expected clone of a missing repository to fail")
	}
	if strings.Contains(err.Error(), "super-secret-token") {
		t.Fatalf("token leaked in error: %v", err)
	}
}
