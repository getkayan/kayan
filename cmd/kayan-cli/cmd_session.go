package main

import (
	"fmt"
)

// ---- Session Commands ----

func (c *CLI) sessionCommand(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: kayan-cli session <subcommand>")
	}

	sub := args[0]
	args = args[1:]

	switch sub {
	case "list":
		return c.listSessions(args)
	case "revoke":
		if len(args) < 1 {
			return fmt.Errorf("usage: kayan-cli session revoke <id>")
		}
		return c.revokeSession(args[0])
	default:
		return fmt.Errorf("unknown session subcommand: %s", sub)
	}
}

func (c *CLI) listSessions(args []string) error {
	opts := parseArgs(args)
	query := buildQuery(opts, "limit", "offset", "user", "tenant")

	resp, err := c.get("/admin/sessions" + query)
	if err != nil {
		return err
	}
	return prettyPrint(resp)
}

func (c *CLI) revokeSession(id string) error {
	return c.delete("/admin/sessions/" + id)
}
