package main

import (
	"fmt"
	"io"
	"strings"
)

// The release suite stamps these with -ldflags -X (.goreleaser.yaml); a local build
// leaves them empty. The linker ignores an -X naming a variable that doesn't exist.
var version, buildRepo, buildServer, buildTime string

func printVersion(out io.Writer) {
	if version == "" {
		fmt.Fprintln(out, "romaine-auth: development build, not from CI")
		return
	}
	fmt.Fprintln(out, "romaine-auth", version)
	if buildRepo != "" && buildServer != "" {
		fmt.Fprintln(out, "from", strings.TrimRight(buildServer, "/")+"/"+buildRepo)
	}
	if buildTime != "" {
		fmt.Fprintln(out, "built", buildTime)
	}
}
