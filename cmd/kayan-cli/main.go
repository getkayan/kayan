package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

// Version is set at build time
var Version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	cli := &CLI{
		BaseURL: getEnv("KAYAN_URL", "http://localhost:8080"),
		Token:   os.Getenv("KAYAN_TOKEN"),
		Client:  &http.Client{Timeout: 30 * time.Second},
	}

	var err error
	switch cmd {
	case "user", "users":
		err = cli.userCommand(args)
	case "tenant", "tenants":
		err = cli.tenantCommand(args)
	case "role", "roles":
		err = cli.roleCommand(args)
	case "session", "sessions":
		err = cli.sessionCommand(args)
	case "audit":
		err = cli.auditCommand(args)
	case "health":
		err = cli.healthCommand(args)
	case "init":
		err = initCommand(args)
	case "generate", "gen":
		err = generateCommand(args)
	case "version":
		fmt.Printf("kayan-cli %s\n", Version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`kayan-cli - Kayan IAM Command Line Interface

Usage:
  kayan-cli <command> [subcommand] [options]

Environment Variables:
  KAYAN_URL    Base URL of Kayan server (default: http://localhost:8080)
  KAYAN_TOKEN  Admin authentication token

Commands:
  user      Manage users
    list    [--tenant=ID] [--limit=N] [--offset=N] [--query=Q]
    get     <id>
    create  --email=EMAIL [--password=PWD] [--tenant=ID]
    update  <id> [--email=EMAIL] [--state=STATE]
    delete  <id>
    lock    <id> [--reason=REASON]
    unlock  <id>
    sessions <id>           List user sessions
    revoke-sessions <id>    Revoke all user sessions

  tenant    Manage tenants
    list    [--limit=N] [--offset=N]
    get     <id>
    create  --name=NAME [--domain=DOMAIN]
    update  <id> [--name=NAME] [--domain=DOMAIN]
    delete  <id>

  role      Manage roles
    list    [--tenant=ID]
    get     <id>
    create  --name=NAME --permissions=P1,P2,P3
    update  <id> [--name=NAME] [--permissions=P1,P2]
    delete  <id>

  session   Manage sessions
    list    [--user=ID] [--tenant=ID] [--limit=N]
    revoke  <id>
    revoke-all [--user=ID] [--tenant=ID]

  audit     Query audit logs
    query   [--user=ID] [--tenant=ID] [--type=TYPE] [--limit=N]
    export  [--user=ID] [--tenant=ID] [--format=json|csv]

  health    Check server health
    live    Liveness check
    ready   Readiness check
    full    Full health report

  init      Scaffold a new Kayan project
    [name]  Project name (default: current directory)

  generate  Generate code
    handler Generate HTTP handlers for a framework

  version   Show CLI version
  help      Show this help

Examples:
  # List all users
  kayan-cli user list

  # Create a new user
  kayan-cli user create --email=admin@example.com --password=secret123

  # Lock a user account
  kayan-cli user lock user-123 --reason="Security incident"

  # Query audit logs
  kayan-cli audit query --user=user-123 --limit=50

  # Check server health
  kayan-cli health full
`)
}
