package client

import (
	"slices"
	"testing"
)

func TestSSHArgvAsksForATerminalOnlyWhenTold(t *testing.T) {
	command := []string{"tmux", "-T", "sixel", "-L", "at", "attach"}
	for _, tty := range []bool{false, true} {
		argv := sshArgv("KEY", "CERT", "nelson", "nelsonpc", tty, command)
		target := slices.Index(argv, "nelsonpc")
		if target < 2 || argv[target-2] != "-l" || argv[target-1] != "nelson" {
			t.Fatalf("tty=%v: target not after -l USER: %q", tty, argv)
		}
		if !slices.Equal(argv[target+1:], command) {
			t.Fatalf("tty=%v: remote command changed: %q", tty, argv[target+1:])
		}
		if got := slices.Contains(argv[:target], "-t"); got != tty {
			t.Fatalf("tty=%v: -t before the target is %v: %q", tty, got, argv)
		}
		if !slices.Contains(argv[:target], "CertificateFile=CERT") || !slices.Contains(argv[:target], "KEY") {
			t.Fatalf("tty=%v: identity missing: %q", tty, argv)
		}
	}
}
