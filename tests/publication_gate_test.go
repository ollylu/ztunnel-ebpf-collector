package tests

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublicationGate(t *testing.T) {
	hooks, err := filepath.Abs("../.githooks")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name                           string
		public, review, scanOK, wantOK bool
	}{
		{"private_repository", false, true, true, false},
		{"unreviewed_commit", true, false, true, false},
		{"scanner_rejects", true, true, false, false},
		{"reviewed_and_scanned", true, true, true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			base := t.TempDir()
			src := filepath.Join(base, "source")
			remote := filepath.Join(base, "remote.git")
			os.Mkdir(src, 0700)
			run := func(dir string, args ...string) string {
				t.Helper()
				c := exec.Command("git", args...)
				c.Dir = dir
				b, e := c.CombinedOutput()
				if e != nil {
					t.Fatalf("git %v: %s", args, b)
				}
				return strings.TrimSpace(string(b))
			}
			run(src, "init", "-q", "--initial-branch=main")
			run(src, "config", "user.name", "Test")
			run(src, "config", "user.email", "test@example.invalid")
			if e := os.WriteFile(filepath.Join(src, "file.txt"), []byte("synthetic public source\n"), 0600); e != nil {
				t.Fatal(e)
			}
			run(src, "add", "file.txt")
			run(src, "-c", "core.hooksPath=/dev/null", "commit", "-qm", "test")
			run(base, "init", "-q", "--bare", remote)
			run(src, "remote", "add", "origin", remote)
			run(src, "config", "core.hooksPath", hooks)
			if tt.public {
				run(src, "config", "security.publicRelease", "true")
			}
			if tt.review {
				run(src, "config", "security.reviewedPublicSHA", run(src, "rev-parse", "HEAD"))
			}
			scanner := filepath.Join(base, "scanner")
			exit := "1"
			if tt.scanOK {
				exit = "0"
			}
			if e := os.WriteFile(scanner, []byte("#!/bin/sh\nexit "+exit+"\n"), 0700); e != nil {
				t.Fatal(e)
			}
			c := exec.Command("git", "push", "origin", "main")
			c.Dir = src
			c.Env = append(os.Environ(), "GITLEAKS_BIN="+scanner)
			b, e := c.CombinedOutput()
			if (e == nil) != tt.wantOK {
				t.Fatalf("push success=%v want=%v: %s", e == nil, tt.wantOK, b)
			}
		})
	}
}
