package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// CLI holds the client configuration
type CLI struct {
	BaseURL string
	Token   string
	Client  *http.Client
}

// ---- HTTP Helpers ----

func (c *CLI) get(path string) ([]byte, error) {
	return c.request("GET", path, nil)
}

func (c *CLI) post(path string, body interface{}) ([]byte, error) {
	return c.request("POST", path, body)
}

func (c *CLI) patch(path string, body interface{}) ([]byte, error) {
	return c.request("PATCH", path, body)
}

func (c *CLI) delete(path string) error {
	_, err := c.request("DELETE", path, nil)
	if err == nil {
		fmt.Println("Deleted successfully")
	}
	return err
}

func (c *CLI) request(method, path string, body interface{}) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.BaseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(data))
	}

	return data, nil
}

// ---- Utility Functions ----

func parseArgs(args []string) map[string]string {
	opts := make(map[string]string)
	for _, arg := range args {
		if strings.HasPrefix(arg, "--") {
			parts := strings.SplitN(strings.TrimPrefix(arg, "--"), "=", 2)
			if len(parts) == 2 {
				opts[parts[0]] = parts[1]
			} else {
				opts[parts[0]] = "true"
			}
		}
	}
	return opts
}

func buildQuery(opts map[string]string, keys ...string) string {
	var parts []string
	for _, k := range keys {
		// Map CLI arg names to query params
		queryKey := k
		switch k {
		case "query":
			queryKey = "q"
		case "user":
			queryKey = "user_id"
		case "tenant":
			queryKey = "tenant_id"
		}
		if v, ok := opts[k]; ok {
			parts = append(parts, queryKey+"="+v)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "?" + strings.Join(parts, "&")
}

func prettyPrint(data []byte) error {
	var obj interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		fmt.Println(string(data))
		return nil
	}
	out, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
