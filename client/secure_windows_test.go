package client

import (
	"context"
	"regexp"
	"testing"

	"golang.org/x/sys/windows"
)

func TestHomeTokenCacheIsPrivate(t *testing.T) {
	issuingFixture(t, 300)
	if _, err := HomeToken(context.Background(), "shows"); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(homeTokenPath("shows"), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if got := sd.String(); !regexp.MustCompile(`^D:PA?I?\(A;;FA;;;S-[0-9-]+\)\(A;;FA;;;SY\)$`).MatchString(got) {
		t.Fatalf("the cached token must be private: %s", got)
	}
}
