package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
)

// ---- Tenant Commands ----

func (c *CLI) tenantCommand(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: kayan-cli tenant <subcommand>")
	}

	sub := args[0]
	args = args[1:]

	switch sub {
	case "list":
		return c.listTenants(args)
	case "get":
		if len(args) < 1 {
			return fmt.Errorf("usage: kayan-cli tenant get <id>")
		}
		return c.getTenant(args[0])
	case "create":
		return c.createTenant(args)
	case "update":
		if len(args) < 1 {
			return fmt.Errorf("usage: kayan-cli tenant update <id> [options]")
		}
		return c.updateTenant(args[0], args[1:])
	case "delete":
		if len(args) < 1 {
			return fmt.Errorf("usage: kayan-cli tenant delete <id>")
		}
		return c.deleteTenant(args[0])
	default:
		return fmt.Errorf("unknown tenant subcommand: %s", sub)
	}
}

func (c *CLI) listTenants(args []string) error {
	opts := parseArgs(args)
	query := buildQuery(opts, "limit", "offset")

	resp, err := c.get("/admin/tenants" + query)
	if err != nil {
		return err
	}

	var result struct {
		Data []struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Domain string `json:"domain"`
			Active bool   `json:"active"`
		} `json:"data"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tDOMAIN\tACTIVE")
	for _, t := range result.Data {
		fmt.Fprintf(w, "%s\t%s\t%s\t%v\n", t.ID, t.Name, t.Domain, t.Active)
	}
	w.Flush()
	fmt.Printf("\nTotal: %d\n", result.Total)
	return nil
}

func (c *CLI) getTenant(id string) error {
	resp, err := c.get("/admin/tenants/" + id)
	if err != nil {
		return err
	}
	return prettyPrint(resp)
}

func (c *CLI) createTenant(args []string) error {
	opts := parseArgs(args)
	body := map[string]interface{}{}

	if name, ok := opts["name"]; ok {
		body["name"] = name
	} else {
		return fmt.Errorf("--name is required")
	}
	if domain, ok := opts["domain"]; ok {
		body["domain"] = domain
	}

	resp, err := c.post("/admin/tenants", body)
	if err != nil {
		return err
	}
	return prettyPrint(resp)
}

func (c *CLI) updateTenant(id string, args []string) error {
	opts := parseArgs(args)
	body := map[string]interface{}{}

	if name, ok := opts["name"]; ok {
		body["name"] = name
	}
	if domain, ok := opts["domain"]; ok {
		body["domain"] = domain
	}

	resp, err := c.patch("/admin/tenants/"+id, body)
	if err != nil {
		return err
	}
	return prettyPrint(resp)
}

func (c *CLI) deleteTenant(id string) error {
	return c.delete("/admin/tenants/" + id)
}
