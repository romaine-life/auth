package client

import (
	"runtime"
	"syscall"

	"golang.org/x/sys/windows"
)

func openBrowser(target string) error {
	verb, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return err
	}
	uri, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	const coinitApartmentThreaded = 0x2
	const coinitDisableOLE1DDE = 0x4
	// S_FALSE also initializes COM successfully and requires a matching release.
	if err := windows.CoInitializeEx(0, coinitApartmentThreaded|coinitDisableOLE1DDE); err != nil && err != syscall.Errno(1) {
		return err
	}
	defer windows.CoUninitialize()
	return windows.ShellExecute(0, verb, uri, nil, nil, windows.SW_SHOWNORMAL)
}
