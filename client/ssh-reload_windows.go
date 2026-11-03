package client

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"time"
)

func requireHostAdmin() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("SSH host setup requires an elevated administrator")
	}
	return nil
}
func protectHostPath(path string, directory bool) error {
	inheritance := ""
	if directory {
		inheritance = "OICI"
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(A;" + inheritance + ";FA;;;SY)(A;" + inheritance + ";FA;;;BA)")
	if e != nil {
		return e
	}
	acl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

func reloadSSH(ctx context.Context) error {
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, e := m.OpenService("sshd")
	if e != nil {
		return e
	}
	defer s.Close()
	status, e := s.Query()
	if e != nil {
		return e
	}
	if status.State == svc.Running {
		if _, e = s.Control(svc.Stop); e != nil {
			return e
		}
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		state, e := s.Query()
		if e != nil {
			return e
		}
		if state.State == svc.Stopped {
			return s.Start()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errors.New("sshd did not stop for configuration reload")
}
