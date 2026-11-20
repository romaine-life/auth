package main

import (
	"strings"
	"testing"
)

func stamp(t *testing.T, ver, repo, server, built string) {
	t.Helper()
	old := [4]string{version, buildRepo, buildServer, buildTime}
	t.Cleanup(func() { version, buildRepo, buildServer, buildTime = old[0], old[1], old[2], old[3] })
	version, buildRepo, buildServer, buildTime = ver, repo, server, built
}

func TestVersionShowsTheStamp(t *testing.T) {
	stamp(t, "v1.4.0", "romaine-life/auth", "https://forgejo.romaine.life/", "2026-11-19T22:00:00.000Z")
	var out strings.Builder
	printVersion(&out)
	want := "romaine-auth v1.4.0\nfrom https://forgejo.romaine.life/romaine-life/auth\nbuilt 2026-11-19T22:00:00.000Z\n"
	if out.String() != want {
		t.Errorf("got %q, want %q", out.String(), want)
	}
}

func TestVersionSaysAnUnstampedBuildIsLocal(t *testing.T) {
	stamp(t, "", "", "", "")
	var out strings.Builder
	printVersion(&out)
	if out.String() != "romaine-auth: development build, not from CI\n" {
		t.Errorf("got %q", out.String())
	}
}
