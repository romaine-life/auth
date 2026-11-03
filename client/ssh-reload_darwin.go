package client

import "context"

// macOS socket activation launches a new sshd with the current config per connection.
func reloadSSH(context.Context) error { return nil }
