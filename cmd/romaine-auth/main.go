package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/romaine-life/auth/client"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "romaine-auth:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("use enroll NAME, user-login, whoami [--human], token --out FILE [--audience openproject|openbao], or ssh --user USER HOST [COMMAND...]")
	}
	ctx := context.Background()
	dir := client.ConfigDir()
	switch args[0] {
	case "ssh-host":
		flags := flag.NewFlagSet("ssh-host", flag.ContinueOnError)
		user := flags.String("user", "", "local OS login")
		file := flags.String("principals", "", "file listing explicit authorized machine principals")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *file == "" || *user == "" {
			return errors.New("ssh-host --user USER --principals FILE")
		}
		data, err := os.ReadFile(*file)
		if err != nil {
			return err
		}
		return client.InstallSSHHostTrust(ctx, *user, strings.Fields(string(data)))
	case "grant":
		if len(args) != 3 {
			return errors.New("grant MACHINE-SUBJECT APPS-JSON-FILE")
		}
		data, err := os.ReadFile(args[2])
		if err != nil {
			return err
		}
		return client.SetMachineGrants(ctx, args[1], json.RawMessage(data))
	case "enroll":
		if len(args) != 2 {
			return errors.New("enroll needs the machine's name")
		}
		reg, err := client.Enroll(ctx, args[1])
		if err != nil {
			return err
		}
		fmt.Printf("Enrolled machine %s (%s).\n", reg.Name, reg.Subject)
		return nil
	case "user-login":
		if err := client.UserLogin(ctx, dir); err != nil {
			return err
		}
		fmt.Println("Personal sign-in saved.")
		return nil
	case "whoami":
		var token string
		var err error
		if len(args) == 2 && args[1] == "--human" {
			token, err = client.ReadHumanToken(dir)
		} else if len(args) == 1 {
			token, err = client.ReadMachineToken(dir)
		} else {
			return errors.New("whoami accepts only --human")
		}
		if err != nil {
			return err
		}
		claims, err := client.ParseClaims(token)
		if err != nil {
			return err
		}
		b, _ := json.Marshal(map[string]any{"subject": claims.Sub, "email": claims.Email, "name": claims.Name, "role": claims.Role, "purpose": claims.Purpose})
		fmt.Println(string(b))
		return nil
	case "token":
		flags := flag.NewFlagSet("token", flag.ContinueOnError)
		out := flags.String("out", "", "protected output file (required)")
		aud := flags.String("audience", "", "machine token audience")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *out == "" || flags.NArg() != 0 {
			return errors.New("token requires --out FILE; credentials are never printed")
		}
		fields := map[string]string{}
		if *aud != "" {
			fields["audience"] = *aud
		}
		result, err := client.Exchange(ctx, fields)
		if err != nil {
			return err
		}
		if result.Token == "" {
			return errors.New("exchange returned no token")
		}
		return client.Save(*out, result)
	case "ssh":
		flags := flag.NewFlagSet("ssh", flag.ContinueOnError)
		user := flags.String("user", "", "destination OS login")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() < 1 || *user == "" {
			return errors.New("ssh --user USER HOST [COMMAND...]")
		}
		return client.SSH(ctx, flags.Arg(0), *user, flags.Args()[1:])
	case "op":
		if len(args) < 3 || (args[1] != "get" && args[1] != "post" && args[1] != "patch") {
			return errors.New("op get|post|patch /api/v3/PATH [BODY-FILE]")
		}
		if !strings.HasPrefix(args[2], "/api/v3/") {
			return errors.New("an OpenProject API path is required")
		}
		var body []byte
		var err error
		if len(args) > 3 {
			if args[3] == "--body-stdin" {
				body, err = io.ReadAll(io.LimitReader(os.Stdin, 10<<20))
			} else {
				body, err = os.ReadFile(filepath.Clean(args[3]))
			}
			if err != nil {
				return err
			}
		}
		return client.OpenProjectRequest(ctx, strings.ToUpper(args[1]), args[2], body, os.Stdout)
	default:
		return errors.New("unknown command")
	}
}
