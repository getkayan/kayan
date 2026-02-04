package main

import (
	"fmt"
)

// ---- Audit Commands ----

func (c *CLI) auditCommand(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: kayan-cli audit <subcommand>")
	}

	sub := args[0]
	args = args[1:]

	switch sub {
	case "query":
		return c.queryAudit(args)
	case "export":
		return c.exportAudit(args)
	default:
		return fmt.Errorf("unknown audit subcommand: %s", sub)
	}
}

func (c *CLI) queryAudit(args []string) error {
	opts := parseArgs(args)
	query := buildQuery(opts, "limit", "offset", "user_id", "tenant_id", "type")

	resp, err := c.get("/admin/audit" + query)
	if err != nil {
		return err
	}
	return prettyPrint(resp)
}

func (c *CLI) exportAudit(args []string) error {
	opts := parseArgs(args)
	format := "json"
	if f, ok := opts["format"]; ok {
		format = f
	}
	query := buildQuery(opts, "user_id", "tenant_id")
	if query == "" {
		query = "?format=" + format
	} else {
		query += "&format=" + format
	}

	resp, err := c.get("/admin/audit/export" + query)
	if err != nil {
		return err
	}
	fmt.Println(string(resp))
	return nil
}
