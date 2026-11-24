package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/romaine-life/auth/client"
)

const azureUsage = "use azure request --reason TEXT [--minutes N] (ask for Azure access, wait for approval, then sign in) or azure login (sign in again while a grant lasts)"

// runAzure is `romaine-auth azure`: Azure access on an administrator's approval (AUT-9).
func runAzure(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New(azureUsage)
	}
	switch args[0] {
	case "request":
		flags := flag.NewFlagSet("azure request", flag.ContinueOnError)
		reason := flags.String("reason", "", "what the access is for, shown to the approver (required)")
		minutes := flags.Int("minutes", 60, "how long the access lasts, 15 to 480")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if strings.TrimSpace(*reason) == "" || flags.NArg() != 0 {
			return errors.New("azure request requires --reason TEXT")
		}
		req, err := client.RequestAzureAccess(ctx, *reason, *minutes)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Requested Azure access for %d minutes. Approve it at %s (the request lapses at %s).\n",
			req.Minutes, req.ApproveURL, client.FormatUnix(req.RequestExpiresAt))
		fmt.Fprintln(os.Stderr, "Waiting for the decision...")
		decided, err := client.WaitAzureAccess(ctx, req.ID)
		if err != nil {
			return err
		}
		if decided.Status != "approved" {
			return fmt.Errorf("the request was %s", decided.Status)
		}
		fmt.Fprintf(os.Stderr, "Approved by %s until %s.\n", decided.DecidedBy, client.FormatUnix(decided.GrantExpiresAt))
		return azureLogin(ctx)
	case "login":
		if len(args) != 1 {
			return errors.New("azure login takes no arguments")
		}
		return azureLogin(ctx)
	default:
		return errors.New(azureUsage)
	}
}

func azureLogin(ctx context.Context) error {
	t, err := client.GetAzureToken(ctx)
	if err != nil {
		return err
	}
	if err := client.AzureLogin(ctx, t); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Azure CLI signed in as the azure-access identity. Its access token lasts about an hour; run romaine-auth azure login again for more, until the grant ends at %s.\n",
		client.FormatUnix(t.GrantExpiresAt))
	return nil
}
