package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/romaine-life/auth/client"
)

// Git Bash rewrites /api/v3/x to C:/Program Files/Git/api/v3/x before this program sees it.
var rewrittenOPPath = regexp.MustCompile(`^[A-Za-z]:/.*?(/api/v3/)`)

func opPath(arg string) string {
	return rewrittenOPPath.ReplaceAllString(arg, "$1")
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "romaine-auth:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("use enroll NAME, user-login, whoami [--human], token --out FILE [--audience openproject], home-token --role ROLE --out FILE, bao get|list|post|patch|delete PATH, ssh [-t] --user USER HOST [COMMAND...], azure request --reason TEXT [--minutes N] | azure login, break-glass request --reason TEXT --session ID [--minutes N] | break-glass status --session ID [--json], cluster token, tailnet join [--force], or version")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	dir := client.ConfigDir()
	switch args[0] {
	case "version":
		printVersion(os.Stdout)
		return nil
	case "ssh-host":
		flags := flag.NewFlagSet("ssh-host", flag.ContinueOnError)
		user := flags.String("user", "", "local OS login")
		file := flags.String("principals", "", "file listing explicit authorized machine principals")
		userScope := flags.Bool("user-scope", false, "install trust in the current Unix account's authorized_keys")
		check := flags.Bool("check", false, "change nothing: print current, or each part of the host trust that differs")
		installed := flags.Bool("installed", false, "change nothing: print each OS login with installed machine trust, or none")
		remove := flags.Bool("remove", false, "remove the login's machine trust; the last login's removal also removes the CA key and sshd_config block")
		host := flags.String("host", "", "another name callers reach this host by, accepted in principals beside its own")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		usage := errors.New("ssh-host --user USER --principals FILE [--host NAME] [--check | --user-scope], ssh-host --user USER --remove, or ssh-host --installed")
		if *installed {
			if *user != "" || *file != "" || *check || *userScope || *remove || *host != "" {
				return usage
			}
			logins, err := client.InstalledSSHHostLogins()
			if err != nil {
				return err
			}
			if len(logins) == 0 {
				logins = []string{"none"}
			}
			fmt.Println(strings.Join(logins, "\n"))
			return nil
		}
		if *remove {
			if *user == "" || *file != "" || *check || *userScope || *host != "" {
				return usage
			}
			return client.RemoveSSHHostTrust(ctx, *user)
		}
		if *file == "" || *user == "" || (*check && *userScope) || (*host != "" && *userScope) {
			return usage
		}
		var names []string
		if *host != "" {
			names = []string{*host}
		}
		data, err := os.ReadFile(*file)
		if err != nil {
			return err
		}
		if *check {
			differences, err := client.SSHHostTrustDifferences(ctx, *user, strings.Fields(string(data)), names...)
			if err != nil {
				return err
			}
			if len(differences) == 0 {
				differences = []string{"current"}
			}
			fmt.Println(strings.Join(differences, "\n"))
			return nil
		}
		if *userScope {
			return client.InstallSSHUserTrust(ctx, *user, strings.Fields(string(data)))
		}
		return client.InstallSSHHostTrust(ctx, *user, strings.Fields(string(data)), names...)
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
		// OpenProject answers at home only: its token comes from the machine's own client in
		// OpenBao, as `op` gets it, never from auth.romaine.life's exchange (OPADMIN-23).
		var result client.Credentials
		var err error
		if *aud == "openproject" {
			result, err = client.ReadOpenProjectCredentials(ctx)
		} else {
			fields := map[string]string{}
			if *aud != "" {
				fields["audience"] = *aud
			}
			result, err = client.Exchange(ctx, fields)
		}
		if err != nil {
			return err
		}
		if result.Token == "" {
			return errors.New("exchange returned no token")
		}
		return client.Save(*out, result)
	case "tailnet":
		flags := flag.NewFlagSet("tailnet", flag.ContinueOnError)
		force := flags.Bool("force", false, "sign in again even when the node is running")
		if len(args) < 2 || args[1] != "join" {
			return errors.New("tailnet join [--force]")
		}
		if err := flags.Parse(args[2:]); err != nil {
			return err
		}
		msg, err := client.JoinTailnet(ctx, *force)
		if err != nil {
			return err
		}
		fmt.Println(msg)
		return nil
	case "azure":
		return runAzure(ctx, args[1:])
	case "break-glass":
		return runBreakGlass(ctx, args[1:])
	case "cluster":
		return runCluster(ctx, args[1:])
	case "home-token":
		flags := flag.NewFlagSet("home-token", flag.ContinueOnError)
		out := flags.String("out", "", "protected output file (required)")
		role := flags.String("role", "", "the home service's OpenBao token role (required)")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *out == "" || *role == "" || flags.NArg() != 0 {
			return errors.New("home-token requires --role ROLE and --out FILE; credentials are never printed")
		}
		result, err := client.HomeToken(ctx, *role)
		if err != nil {
			return err
		}
		return client.Save(*out, result)
	case "ssh":
		flags := flag.NewFlagSet("ssh", flag.ContinueOnError)
		user := flags.String("user", "", "destination OS login")
		tty := flags.Bool("t", false, "request a terminal, for an interactive remote command")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() < 1 || *user == "" {
			return errors.New("ssh [-t] --user USER HOST [COMMAND...]")
		}
		return client.SSH(ctx, flags.Arg(0), *user, *tty, flags.Args()[1:])
	case "op":
		if len(args) < 3 || (args[1] != "get" && args[1] != "post" && args[1] != "patch") {
			return errors.New("op get|post|patch /api/v3/PATH [BODY-FILE]")
		}
		path := opPath(args[2])
		if !strings.HasPrefix(path, "/api/v3/") {
			return errors.New("an OpenProject API path is required")
		}
		body, err := requestBody(args[3:])
		if err != nil {
			return err
		}
		return client.OpenProjectRequest(ctx, strings.ToUpper(args[1]), path, body, os.Stdout)
	case "bao":
		methods := map[string]string{"get": "GET", "list": "LIST", "post": "POST", "patch": "PATCH", "delete": "DELETE"}
		if len(args) < 3 || len(args) > 4 || methods[args[1]] == "" {
			return errors.New("bao get|list|post|patch|delete PATH [BODY-FILE | --body-stdin], PATH under /v1/ such as secret/data/home/ntfy")
		}
		body, err := requestBody(args[3:])
		if err != nil {
			return err
		}
		return client.BaoRequest(ctx, methods[args[1]], args[2], body, os.Stdout)
	default:
		return errors.New("unknown command")
	}
}

// requestBody reads an API call's body from the file named, or stdin for --body-stdin,
// so a secret never goes on the command line.
func requestBody(args []string) ([]byte, error) {
	if len(args) == 0 {
		return nil, nil
	}
	if args[0] == "--body-stdin" {
		return io.ReadAll(io.LimitReader(os.Stdin, 10<<20))
	}
	return os.ReadFile(filepath.Clean(args[0]))
}
