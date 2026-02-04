package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"
)

// ---- User Commands ----

func (c *CLI) userCommand(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: kayan-cli user <subcommand>")
	}

	sub := args[0]
	args = args[1:]

	switch sub {
	case "list":
		return c.listUsers(args)
	case "get":
		if len(args) < 1 {
			return fmt.Errorf("usage: kayan-cli user get <id>")
		}
		return c.getUser(args[0])
	case "create":
		return c.createUser(args)
	case "update":
		if len(args) < 1 {
			return fmt.Errorf("usage: kayan-cli user update <id> [options]")
		}
		return c.updateUser(args[0], args[1:])
	case "delete":
		if len(args) < 1 {
			return fmt.Errorf("usage: kayan-cli user delete <id>")
		}
		return c.deleteUser(args[0])
	case "lock":
		if len(args) < 1 {
			return fmt.Errorf("usage: kayan-cli user lock <id> [--reason=REASON]")
		}
		return c.lockUser(args[0], args[1:])
	case "unlock":
		if len(args) < 1 {
			return fmt.Errorf("usage: kayan-cli user unlock <id>")
		}
		return c.unlockUser(args[0])
	case "sessions":
		if len(args) < 1 {
			return fmt.Errorf("usage: kayan-cli user sessions <id>")
		}
		return c.listUserSessions(args[0])
	case "revoke-sessions":
		if len(args) < 1 {
			return fmt.Errorf("usage: kayan-cli user revoke-sessions <id>")
		}
		return c.revokeUserSessions(args[0])
	default:
		return fmt.Errorf("unknown user subcommand: %s", sub)
	}
}

func (c *CLI) listUsers(args []string) error {
	opts := parseArgs(args)
	query := buildQuery(opts, "limit", "offset", "q", "tenant")

	resp, err := c.get("/admin/users" + query)
	if err != nil {
		return err
	}

	var result struct {
		Data []struct {
			ID        string    `json:"id"`
			Email     string    `json:"email"`
			State     string    `json:"state"`
			CreatedAt time.Time `json:"created_at"`
		} `json:"data"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tEMAIL\tSTATE\tCREATED")
	for _, u := range result.Data {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", u.ID, u.Email, u.State, u.CreatedAt.Format(time.RFC3339))
	}
	w.Flush()
	fmt.Printf("\nTotal: %d\n", result.Total)
	return nil
}

func (c *CLI) getUser(id string) error {
	resp, err := c.get("/admin/users/" + id)
	if err != nil {
		return err
	}
	return prettyPrint(resp)
}

func (c *CLI) createUser(args []string) error {
	opts := parseArgs(args)
	body := map[string]interface{}{}

	if email, ok := opts["email"]; ok {
		body["email"] = email
		body["traits"] = map[string]string{"email": email}
	} else {
		return fmt.Errorf("--email is required")
	}
	if pwd, ok := opts["password"]; ok {
		body["password"] = pwd
	}
	if tenant, ok := opts["tenant"]; ok {
		body["tenant_id"] = tenant
	}

	resp, err := c.post("/admin/users", body)
	if err != nil {
		return err
	}
	return prettyPrint(resp)
}

func (c *CLI) updateUser(id string, args []string) error {
	opts := parseArgs(args)
	body := map[string]interface{}{}

	if email, ok := opts["email"]; ok {
		body["email"] = email
	}
	if state, ok := opts["state"]; ok {
		body["state"] = state
	}

	resp, err := c.patch("/admin/users/"+id, body)
	if err != nil {
		return err
	}
	return prettyPrint(resp)
}

func (c *CLI) deleteUser(id string) error {
	return c.delete("/admin/users/" + id)
}

func (c *CLI) lockUser(id string, args []string) error {
	opts := parseArgs(args)
	body := map[string]string{}
	if reason, ok := opts["reason"]; ok {
		body["reason"] = reason
	}

	_, err := c.post("/admin/users/"+id+"/lock", body)
	if err != nil {
		return err
	}
	fmt.Println("User locked successfully")
	return nil
}

func (c *CLI) unlockUser(id string) error {
	_, err := c.post("/admin/users/"+id+"/unlock", nil)
	if err != nil {
		return err
	}
	fmt.Println("User unlocked successfully")
	return nil
}

func (c *CLI) listUserSessions(id string) error {
	resp, err := c.get("/admin/users/" + id + "/sessions")
	if err != nil {
		return err
	}
	return prettyPrint(resp)
}

func (c *CLI) revokeUserSessions(id string) error {
	return c.delete("/admin/users/" + id + "/sessions")
}
