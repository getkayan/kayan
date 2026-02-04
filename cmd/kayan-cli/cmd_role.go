package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

// ---- Role Commands ----

func (c *CLI) roleCommand(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: kayan-cli role <subcommand>")
	}

	sub := args[0]
	args = args[1:]

	switch sub {
	case "list":
		return c.listRoles(args)
	case "get":
		if len(args) < 1 {
			return fmt.Errorf("usage: kayan-cli role get <id>")
		}
		return c.getRole(args[0])
	case "create":
		return c.createRole(args)
	case "delete":
		if len(args) < 1 {
			return fmt.Errorf("usage: kayan-cli role delete <id>")
		}
		return c.deleteRole(args[0])
	default:
		return fmt.Errorf("unknown role subcommand: %s", sub)
	}
}

func (c *CLI) listRoles(args []string) error {
	opts := parseArgs(args)
	query := buildQuery(opts, "limit", "offset", "tenant")

	resp, err := c.get("/admin/roles" + query)
	if err != nil {
		return err
	}

	var result struct {
		Data []struct {
			ID          string   `json:"id"`
			Name        string   `json:"name"`
			Permissions []string `json:"permissions"`
		} `json:"data"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tPERMISSIONS")
	for _, r := range result.Data {
		perms := strings.Join(r.Permissions, ", ")
		if len(perms) > 50 {
			perms = perms[:47] + "..."
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", r.ID, r.Name, perms)
	}
	w.Flush()
	fmt.Printf("\nTotal: %d\n", result.Total)
	return nil
}

func (c *CLI) getRole(id string) error {
	resp, err := c.get("/admin/roles/" + id)
	if err != nil {
		return err
	}
	return prettyPrint(resp)
}

func (c *CLI) createRole(args []string) error {
	opts := parseArgs(args)
	body := map[string]interface{}{}

	if name, ok := opts["name"]; ok {
		body["name"] = name
	} else {
		return fmt.Errorf("--name is required")
	}
	if perms, ok := opts["permissions"]; ok {
		body["permissions"] = strings.Split(perms, ",")
	} else {
		return fmt.Errorf("--permissions is required")
	}

	resp, err := c.post("/admin/roles", body)
	if err != nil {
		return err
	}
	return prettyPrint(resp)
}

func (c *CLI) deleteRole(id string) error {
	return c.delete("/admin/roles/" + id)
}
