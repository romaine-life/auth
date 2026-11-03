package client

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"unsafe"
)

func publicJWK() (map[string]string, error) {
	s, err := openPlatformKey(false)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	k := s.(*platformKey)
	format, _ := windows.UTF16PtrFromString("ECCPUBLICBLOB")
	out := make([]byte, 72)
	var size uint32
	st, _, _ := ncrypt.NewProc("NCryptExportKey").Call(k.key, 0, uintptr(unsafe.Pointer(format)), 0, uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)), uintptr(unsafe.Pointer(&size)), 0)
	if st != 0 {
		return nil, fmt.Errorf("exporting TPM public key: %s", ncryptStatus(st))
	}
	if size != 72 || binary.LittleEndian.Uint32(out[:4]) != 0x31534345 || binary.LittleEndian.Uint32(out[4:8]) != 32 {
		return nil, errors.New("unexpected TPM public key")
	}
	return map[string]string{"kty": "EC", "crv": "P-256", "x": base64.RawURLEncoding.EncodeToString(out[8:40]), "y": base64.RawURLEncoding.EncodeToString(out[40:72])}, nil
}
func protectFile(path string) error {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)")
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
