package client

import (
	"testing"
	"time"
)

// A call the TPM turns away for being busy is tried again until it goes
// through; any other answer, success or failure, returns at once; and a TPM
// busy past tpmBusyWait returns its busy status (AUT-5).
func TestWhileBusyRetriesOnlyABusyTPM(t *testing.T) {
	answers := []uintptr{nteDeviceNotReady, tpm20Canceled, nteDeviceNotReady, 0}
	calls := 0
	if st := whileBusy(func() uintptr { calls++; return answers[calls-1] }); st != 0 || calls != 4 {
		t.Errorf("busy three times then through: status %#x after %d calls", st, calls)
	}

	calls = 0
	const notFound = 0x80090016
	if st := whileBusy(func() uintptr { calls++; return notFound }); st != notFound || calls != 1 {
		t.Errorf("a missing key: status %#x after %d calls, want one call", st, calls)
	}

	old := tpmBusyWait
	tpmBusyWait = 50 * time.Millisecond
	t.Cleanup(func() { tpmBusyWait = old })
	start := time.Now()
	if st := whileBusy(func() uintptr { return tpm20Canceled }); st != tpm20Canceled {
		t.Errorf("a TPM busy throughout: status %#x", st)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("a TPM busy throughout held on for %v", took)
	}
}
