package client

import (
	"fmt"
	"math/rand/v2"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The device key lives in the Microsoft Platform Crypto Provider (the TPM), under the
// Windows user, and can't be exported: only this user's session on this PC can sign
// with it.
const platformCryptoProvider = "Microsoft Platform Crypto Provider"

// The TPM serves one command at a time and turns others away while it is busy:
// the provider isn't ready (NTE_DEVICE_NOT_READY) or the TPM cancels the command
// (TPM_20_E_CANCELED). Sixty-four signings at once, as every window of an app
// restarting together asks, saw both, mostly the first (AUT-5). Both clear when
// the others finish, and the TPM has no event to say so, so a busy call is tried
// again after a short, growing, jittered wait, for up to tpmBusyWait.
const (
	nteDeviceNotReady = 0x80090030
	tpm20Canceled     = 0x80280909
)

var tpmBusyWait = 10 * time.Second

// whileBusy runs call until it isn't turned away for the TPM being busy, or
// tpmBusyWait has passed, and returns its last status.
func whileBusy(call func() uintptr) uintptr {
	deadline := time.Now().Add(tpmBusyWait)
	wait := 5 * time.Millisecond
	for {
		st := call()
		if s := uint32(st); s != nteDeviceNotReady && s != tpm20Canceled || time.Now().After(deadline) {
			return st
		}
		time.Sleep(wait + rand.N(wait))
		wait = min(wait*2, 200*time.Millisecond)
	}
}

// ncryptSilentFlag stops CNG from ever showing a prompt; a key that would need one
// fails instead.
const ncryptSilentFlag = 0x40

var (
	ncrypt                 = windows.NewLazySystemDLL("ncrypt.dll")
	procOpenStorageProvide = ncrypt.NewProc("NCryptOpenStorageProvider")
	procOpenKey            = ncrypt.NewProc("NCryptOpenKey")
	procSignHash           = ncrypt.NewProc("NCryptSignHash")
	procFreeObject         = ncrypt.NewProc("NCryptFreeObject")
)

type platformKey struct {
	provider uintptr
	key      uintptr
}

func openPlatformKey(create bool) (signer, error) {
	providerName, _ := windows.UTF16PtrFromString(platformCryptoProvider)
	keyName, _ := windows.UTF16PtrFromString("romaine-device")
	var k platformKey
	if st := whileBusy(func() uintptr {
		st, _, _ := procOpenStorageProvide.Call(uintptr(unsafe.Pointer(&k.provider)), uintptr(unsafe.Pointer(providerName)), 0)
		return st
	}); st != 0 {
		return nil, fmt.Errorf("opening the TPM key store: %s", ncryptStatus(st))
	}
	if st := whileBusy(func() uintptr {
		st, _, _ := procOpenKey.Call(k.provider, uintptr(unsafe.Pointer(&k.key)), uintptr(unsafe.Pointer(keyName)), 0, ncryptSilentFlag)
		return st
	}); st != 0 {
		if !create || uint32(st) != 0x80090016 {
			procFreeObject.Call(k.provider)
			return nil, fmt.Errorf("opening TPM key: %s", ncryptStatus(st))
		}
		algorithm, _ := windows.UTF16PtrFromString("ECDSA_P256")
		if code, _, _ := ncrypt.NewProc("NCryptCreatePersistedKey").Call(k.provider, uintptr(unsafe.Pointer(&k.key)), uintptr(unsafe.Pointer(algorithm)), uintptr(unsafe.Pointer(keyName)), 0, 0); code != 0 {
			procFreeObject.Call(k.provider)
			return nil, fmt.Errorf("creating TPM key: %s", ncryptStatus(code))
		}
		if code, _, _ := ncrypt.NewProc("NCryptFinalizeKey").Call(k.key, 0); code != 0 {
			k.Close()
			return nil, fmt.Errorf("finalizing TPM key: %s", ncryptStatus(code))
		}
	}
	return &k, nil
}

func (k *platformKey) SignDigest(digest []byte) ([]byte, error) {
	sig := make([]byte, 64)
	var n uint32
	st := whileBusy(func() uintptr {
		st, _, _ := procSignHash.Call(k.key, 0,
			uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
			uintptr(unsafe.Pointer(&sig[0])), uintptr(len(sig)),
			uintptr(unsafe.Pointer(&n)), ncryptSilentFlag)
		return st
	})
	if st != 0 {
		return nil, fmt.Errorf("signing with TPM key %q: %s", "romaine-device", ncryptStatus(st))
	}
	return sig[:n], nil
}

func (k *platformKey) Close() {
	procFreeObject.Call(k.key)
	procFreeObject.Call(k.provider)
}

// ncryptStatus names a SECURITY_STATUS, which is an HRESULT.
func ncryptStatus(st uintptr) string {
	return fmt.Sprintf("%v (0x%08X)", windows.Errno(st), uint32(st))
}
