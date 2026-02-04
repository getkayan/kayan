package main

import (
	"fmt"
)

// ---- Health Commands ----

func (c *CLI) healthCommand(args []string) error {
	sub := "full"
	if len(args) > 0 {
		sub = args[0]
	}

	var path string
	switch sub {
	case "live":
		path = "/health/live"
	case "ready":
		path = "/health/ready"
	case "full":
		path = "/health"
	default:
		return fmt.Errorf("unknown health subcommand: %s", sub)
	}

	resp, err := c.get(path)
	if err != nil {
		return err
	}
	return prettyPrint(resp)
}
