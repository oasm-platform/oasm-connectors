// Package gitrepo gives repository-scanning connectors (targetTypes: git_org)
// their input contract and a safe checkout.
//
// The platform sends one repository per execution as flat ExecuteJob inputs:
//
//	repository  clone URL (https), e.g. https://github.com/acme/web
//	ref         branch, tag or commit to scan; empty = the default branch
//	username    HTTP basic user for private repositories (optional)
//	token       HTTP basic password / access token (optional)
//
// The token never appears in a URL, a command line or the cloned
// repository's config: it is handed to git as an in-memory
// `http.extraHeader` through GIT_CONFIG_* environment variables of the git
// process only, and the SDK redacts the `token` input in its logs.
package gitrepo

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
)

// Input keys of the repository contract.
const (
	InputRepository = "repository"
	InputRef        = "ref"
	InputUsername   = "username"
	InputToken      = "token"
)

// Inputs is a parsed repository execution input.
type Inputs struct {
	Repository string
	Ref        string
	Username   string
	Token      string
}

// ParseInputs validates the repository inputs of one execution. Only https
// clone URLs are accepted: a file:// or ssh:// URL would let a crafted input
// read the connector's own filesystem or reach unintended hosts.
func ParseInputs(inputs map[string]any) (Inputs, error) {
	str := func(key string) string {
		v, ok := inputs[key]
		if !ok || v == nil {
			return ""
		}
		return strings.TrimSpace(fmt.Sprintf("%v", v))
	}
	in := Inputs{
		Repository: str(InputRepository),
		Ref:        str(InputRef),
		Username:   str(InputUsername),
		Token:      str(InputToken),
	}
	if in.Repository == "" {
		return Inputs{}, errors.New("input \"repository\" is required")
	}
	u, err := url.Parse(in.Repository)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return Inputs{}, fmt.Errorf("input \"repository\" must be an https URL, got %q", redactURL(in.Repository))
	}
	if u.User != nil {
		return Inputs{}, errors.New("input \"repository\" must not embed credentials; use the username/token inputs")
	}
	if strings.HasPrefix(in.Ref, "-") {
		return Inputs{}, fmt.Errorf("input \"ref\" %q is not a valid ref", in.Ref)
	}
	if in.Token != "" && in.Username == "" {
		// GitHub and GitLab both accept any non-empty user with a token.
		in.Username = "x-access-token"
	}
	return in, nil
}

// Checkout is a shallow clone on disk. Call Close when done; it removes the
// directory.
type Checkout struct {
	// Dir is the working tree root.
	Dir string
	// Commit is the checked-out commit SHA.
	Commit string
}

// Close removes the checkout from disk.
func (c *Checkout) Close() error {
	if c == nil || c.Dir == "" {
		return nil
	}
	return os.RemoveAll(c.Dir)
}

// Options tunes Clone.
type Options struct {
	// Depth of the clone; 0 means 1 (the ref's tip only). Secret scanners
	// that walk history set a larger depth.
	Depth int
	// Git is the git binary; empty means "git" on PATH.
	Git string
	// TempDir is the parent of the checkout; empty means os.TempDir().
	TempDir string
}

// Clone shallow-clones in.Repository at in.Ref into a fresh temporary
// directory. The caller owns the returned Checkout and must Close it.
func Clone(ctx context.Context, in Inputs, opts Options) (*Checkout, error) {
	depth := opts.Depth
	if depth <= 0 {
		depth = 1
	}
	gitBin := opts.Git
	if gitBin == "" {
		gitBin = "git"
	}

	dir, err := os.MkdirTemp(opts.TempDir, "oasm-repo-")
	if err != nil {
		return nil, fmt.Errorf("create checkout dir: %w", err)
	}
	checkout := &Checkout{Dir: dir}
	fail := func(err error) (*Checkout, error) {
		_ = checkout.Close()
		return nil, err
	}

	args := []string{"clone", "--quiet", "--no-tags", "--single-branch", fmt.Sprintf("--depth=%d", depth)}
	if in.Ref != "" {
		args = append(args, "--branch", in.Ref)
	}
	args = append(args, "--", in.Repository, dir)
	if _, err := runGit(ctx, gitBin, "", in, args...); err != nil {
		return fail(fmt.Errorf("clone %s: %w", redactURL(in.Repository), err))
	}

	sha, err := runGit(ctx, gitBin, dir, Inputs{}, "rev-parse", "HEAD")
	if err != nil {
		return fail(fmt.Errorf("resolve HEAD: %w", err))
	}
	checkout.Commit = strings.TrimSpace(sha)
	return checkout, nil
}

// runGit runs one git command. Credentials, when present, are passed as an
// Authorization header via GIT_CONFIG_* — scoped to this process, never
// written to disk or argv. Prompts are disabled so a bad token fails fast.
func runGit(ctx context.Context, gitBin, dir string, in Inputs, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, gitBin, args...)
	cmd.Dir = dir
	env := append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=",
		"GCM_INTERACTIVE=never",
	)
	if in.Token != "" {
		basic := base64.StdEncoding.EncodeToString([]byte(in.Username + ":" + in.Token))
		env = append(env,
			"GIT_CONFIG_COUNT=1",
			"GIT_CONFIG_KEY_0=http.extraHeader",
			"GIT_CONFIG_VALUE_0=Authorization: Basic "+basic,
		)
	}
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if in.Token != "" {
			msg = strings.ReplaceAll(msg, in.Token, "<redacted>")
		}
		if msg == "" {
			return "", err
		}
		return "", fmt.Errorf("%w: %s", err, msg)
	}
	return stdout.String(), nil
}

// redactURL strips any userinfo from a URL for error messages.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<invalid url>"
	}
	u.User = nil
	return u.String()
}
