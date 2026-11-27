package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/romaine-life/auth/client"
)

const breakGlassUsage = "use break-glass request --reason TEXT --session ID [--minutes N] (ask for a grant and wait for the decision) or break-glass status --session ID [--json] (exit 0 with the session's active grant, 1 with none)"

// runBreakGlass is `romaine-auth break-glass`: a Claude session's grant past owner-guard, as
// cluster-admin on the home cluster, on an administrator's approval (AHT-209).
func runBreakGlass(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New(breakGlassUsage)
	}
	switch args[0] {
	case "request":
		flags := flag.NewFlagSet("break-glass request", flag.ContinueOnError)
		reason := flags.String("reason", "", "what the grant is for, shown to the approver (required)")
		session := flags.String("session", "", "the Claude session id the grant is for (required)")
		minutes := flags.Int("minutes", 60, "how long the grant lasts, 15 to 480")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if strings.TrimSpace(*reason) == "" || strings.TrimSpace(*session) == "" || flags.NArg() != 0 {
			return errors.New("break-glass request requires --reason TEXT and --session ID")
		}
		req, err := client.RequestBreakGlass(ctx, *reason, *session, *minutes)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Requested break-glass for %d minutes. Approve it at %s (the request lapses at %s).\n",
			req.Minutes, req.ApproveURL, client.FormatUnix(req.RequestExpiresAt))
		fmt.Fprintln(os.Stderr, "Waiting for the decision...")
		decided, err := client.WaitBreakGlass(ctx, req.ID)
		if err != nil {
			return err
		}
		if decided.Status != "approved" {
			return fmt.Errorf("the request was %s", decided.Status)
		}
		fmt.Fprintf(os.Stderr, "Approved by %s until %s.\n", decided.DecidedBy, client.FormatUnix(decided.GrantExpiresAt))
		return nil
	case "status":
		flags := flag.NewFlagSet("break-glass status", flag.ContinueOnError)
		session := flags.String("session", "", "the Claude session id (required)")
		asJSON := flags.Bool("json", false, "print the grant as JSON: {id, session, grantExpiresAt}")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if strings.TrimSpace(*session) == "" || flags.NArg() != 0 {
			return errors.New("break-glass status requires --session ID")
		}
		grant, err := client.SessionBreakGlass(ctx, strings.TrimSpace(*session))
		if err != nil {
			return err
		}
		if grant == nil {
			return fmt.Errorf("session %s has no active break-glass grant", *session)
		}
		if *asJSON {
			b, _ := json.Marshal(grant)
			fmt.Println(string(b))
		} else {
			fmt.Printf("Break-glass grant %s for session %s until %s.\n", grant.ID, grant.Session, client.FormatUnix(grant.GrantExpiresAt))
		}
		return nil
	default:
		return errors.New(breakGlassUsage)
	}
}

// runCluster is `romaine-auth cluster token`: the home cluster's break-glass token as a
// kubeconfig exec plugin's ExecCredential, while this machine holds an active grant.
func runCluster(ctx context.Context, args []string) error {
	if len(args) != 1 || args[0] != "token" {
		return errors.New("cluster token (an ExecCredential for a kubeconfig exec plugin, while a break-glass grant lasts)")
	}
	t, err := client.GetClusterToken(ctx)
	if err != nil {
		return err
	}
	b, err := client.ExecCredential(t)
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
