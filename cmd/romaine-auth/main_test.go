package main

import "testing"

func TestOPPath(t *testing.T) {
	for arg, want := range map[string]string{
		"/api/v3/users/me": "/api/v3/users/me",
		"C:/Program Files/Git/api/v3/work_packages/2660": "/api/v3/work_packages/2660",
		"/api/v3/work_packages?filters=[]":               "/api/v3/work_packages?filters=[]",
		"https://example.com/api/v3/users/me":            "https://example.com/api/v3/users/me",
		"C:/Program Files/Git/users/me":                  "C:/Program Files/Git/users/me",
	} {
		if got := opPath(arg); got != want {
			t.Errorf("opPath(%q) = %q, want %q", arg, got, want)
		}
	}
}
