package main

import (
	"slices"
	"testing"
)

func TestTitleFromMessage(t *testing.T) {
	tests := []struct {
		name, message, want string
	}{
		{
			"single sentence passes through unchanged",
			"Attackers may be able to crash FrontPage by requesting a DOS device.",
			"Attackers may be able to crash FrontPage by requesting a DOS device.",
		},
		{
			"two sentences split at the first break",
			"The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type.",
			"The X-Content-Type-Options header is not set.",
		},
		{
			"three sentences keep only the first",
			"Cobalt Qube 3 admin is running. This may have multiple security problems. Another sentence here.",
			"Cobalt Qube 3 admin is running.",
		},
		{
			"a version number is not a sentence break",
			"Drupal version number 8.5.1 implies that there is a SQL Injection.",
			"Drupal version number 8.5.1 implies that there is a SQL Injection.",
		},
		{
			"lowercase after the period is not a break",
			"Default login/pass could be admin/admin. see the manual for details.",
			"Default login/pass could be admin/admin. see the manual for details.",
		},
		{
			"no trailing period stays whole",
			"PHPList pre 2.6.4 contains a number of vulnerabilities",
			"PHPList pre 2.6.4 contains a number of vulnerabilities",
		},
		{
			"empty stays empty",
			"",
			"",
		},
		{
			"a file path with a period is not a break",
			"Backup file found at /var/www/backup.zip. It contains source.",
			"Backup file found at /var/www/backup.zip.",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := titleFromMessage(tc.message); got != tc.want {
				t.Errorf("titleFromMessage(%q) = %q, want %q", tc.message, got, tc.want)
			}
		})
	}
}

// A title must never be longer than the message it came from, and must always
// be a prefix of it — a split can shorten but never rewrite.
func TestTitleFromMessage_IsAlwaysAPrefix(t *testing.T) {
	msgs := []string{
		"The Tivo Calypso server is running. This page will display the version and platform it is running on.",
		"MySQL 5.0.45 is installed. Upgrade to a newer version.",
		"No sentence break here at all",
		"Weird trailing. ",
	}
	for _, m := range msgs {
		title := titleFromMessage(m)
		if len(title) > len(m) {
			t.Errorf("title %q longer than message %q", title, m)
		}
		if m != "" && title != "" && m[:len(title)] != title {
			t.Errorf("title %q is not a prefix of %q", title, m)
		}
	}
}

// Every real capture finding must end up with a non-empty Name and Description,
// and the Description must be the untruncated message.
func TestRealStdout_TitleAndDescription(t *testing.T) {
	f, ok := parseItemLine(
		`+ [007352] /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type.`,
		"http://nikto-target")
	if !ok {
		t.Fatal("expected a finding")
	}
	const full = "The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type."
	if f.Description != full {
		t.Errorf("Description = %q, want the full message", f.Description)
	}
	if f.Name != "The X-Content-Type-Options header is not set." {
		t.Errorf("Name = %q, want the first sentence", f.Name)
	}
	// The title must be recoverable from the description.
	if f.Description[:len(f.Name)] != f.Name {
		t.Errorf("Name %q is not a prefix of Description %q", f.Name, f.Description)
	}
}

// A single-sentence finding keeps Name == Description. That is not redundant: it
// records that nikto supplied only one sentence, so nothing was withheld.
func TestParseItemLine_SingleSentenceNameEqualsDescription(t *testing.T) {
	f, ok := parseItemLine("+ [000024] /backup.zip: Backup file found, source code disclosure.", "https://example.com")
	if !ok {
		t.Fatal("expected a finding")
	}
	if f.Name != f.Description {
		t.Errorf("Name = %q, Description = %q, want them equal", f.Name, f.Description)
	}
	if !slices.Contains(f.Tags, "nikto-id:000024") {
		t.Errorf("Tags = %v", f.Tags)
	}
}
