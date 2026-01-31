package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
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
	fmt.Println(`kayan-cli - Kayan IAM Command Line Interface

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

// CLI holds the client configuration
type CLI struct {
	BaseURL string
	Token   string
	Client  *http.Client
}

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

// ---- Init Command ----

func initCommand(args []string) error {
	projectName := "."
	if len(args) > 0 {
		projectName = args[0]
	}

	// Create project directory if needed
	if projectName != "." {
		if err := os.MkdirAll(projectName, 0755); err != nil {
			return err
		}
	}

	// Determine module name
	moduleName := projectName
	if projectName == "." {
		// Use current directory name
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		moduleName = filepath.Base(cwd)
	}

	files := map[string]string{
		"main.go":    mainGoTemplate,
		"go.mod":     goModTemplate,
		"README.md":  readmeTemplate,
		".env":       envTemplate,
		".gitignore": gitignoreTemplate,
	}

	for filename, content := range files {
		path := filepath.Join(projectName, filename)
		tmpl, err := template.New(filename).Parse(content)
		if err != nil {
			return fmt.Errorf("template error: %w", err)
		}

		f, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("failed to create %s: %w", filename, err)
		}

		data := map[string]string{"ModuleName": moduleName}
		if err := tmpl.Execute(f, data); err != nil {
			f.Close()
			return err
		}
		f.Close()
		fmt.Printf("  created %s\n", path)
	}

	fmt.Printf("\n✅ Project '%s' created!\n\n", moduleName)
	fmt.Println("Next steps:")
	fmt.Println("  1. cd", projectName)
	fmt.Println("  2. go mod tidy")
	fmt.Println("  3. go run main.go")
	return nil
}

func generateCommand(args []string) error {
	if len(args) < 1 {
		fmt.Println("Usage: kayan-cli generate <type>")
		fmt.Println("Types: handler")
		return nil
	}

	switch args[0] {
	case "handler":
		return generateHandler(args[1:])
	default:
		return fmt.Errorf("unknown generate type: %s", args[0])
	}
}

func generateHandler(args []string) error {
	framework := "echo"
	if len(args) > 0 {
		framework = args[0]
	}

	var content string
	switch framework {
	case "echo":
		content = echoHandlerTemplate
	default:
		return fmt.Errorf("unsupported framework: %s (supported: echo)", framework)
	}

	filename := "handler.go"
	if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
		return err
	}
	fmt.Printf("Generated %s for %s framework\n", filename, framework)
	return nil
}

// ---- Templates ----

var mainGoTemplate = `package main

import (
	"log"

	"github.com/getkayan/kayan-echo"
	"github.com/getkayan/kayan/core/flow"
	"github.com/getkayan/kayan/core/session"
	"github.com/getkayan/kayan/kgorm"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	// Database
	db, err := gorm.Open(sqlite.Open("app.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect database:", err)
	}

	// Auto-migrate schemas
	if err := kgorm.AutoMigrate(db); err != nil {
		log.Fatal("Migration failed:", err)
	}

	// Repositories
	identityRepo := kgorm.NewIdentityRepository(db, func() any { return &kgorm.DefaultIdentity{} })
	sessionRepo := kgorm.NewSessionRepository(db)

	// Managers
	regManager := flow.NewRegistrationManager(identityRepo, func() any { return &kgorm.DefaultIdentity{} })
	loginManager := flow.NewLoginManager(identityRepo, func() any { return &kgorm.DefaultIdentity{} })
	sessManager := session.NewManager(session.NewDatabaseStrategy(sessionRepo))

	// Password strategy
	hasher := flow.NewBcryptHasher(12)
	pwStrategy := flow.NewPasswordStrategy(identityRepo, hasher, "email", func() any { return &kgorm.DefaultIdentity{} })
	regManager.AddStrategy("password", pwStrategy)
	loginManager.AddStrategy("password", pwStrategy)

	// Echo setup
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	// Kayan handler
	h := kayanecho.NewHandler(regManager, loginManager, sessManager, nil)
	h.SetIDGenerator(func() any { return uuid.New().String() })
	h.SetTokenParser(func(t string) (any, error) { return t, nil })

	// Routes
	api := e.Group("/api/v1")
	h.RegisterRoutes(api)

	// Protected routes example
	api.GET("/me", func(c echo.Context) error {
		return c.JSON(200, map[string]string{"message": "Hello from protected route!"})
	}, h.AuthMiddleware)

	log.Println("Starting server on :8080")
	e.Logger.Fatal(e.Start(":8080"))
}
`

var goModTemplate = `module {{.ModuleName}}

go 1.21

require (
	github.com/getkayan/kayan v1.0.0
	github.com/getkayan/kayan-echo v1.0.0
	github.com/google/uuid v1.6.0
	github.com/labstack/echo/v4 v4.14.0
	gorm.io/driver/sqlite v1.5.0
	gorm.io/gorm v1.25.0
)
`

var readmeTemplate = `# {{.ModuleName}}

A Kayan-powered authentication service.

## Quick Start

` + "```" + `bash
go mod tidy
go run main.go
` + "```" + `

## API Endpoints

- POST /api/v1/registration - Register new user
- POST /api/v1/login - Login
- GET /api/v1/whoami - Get current user
- GET /api/v1/me - Protected route example

## Environment

Copy .env to configure:
- PORT - Server port (default: 8080)
- DATABASE_URL - Database connection string
`

var envTemplate = `PORT=8080
DATABASE_URL=app.db
`

var gitignoreTemplate = `# Binaries
*.exe
*.dll
*.so
*.dylib

# Database
*.db
*.sqlite

# IDE
.idea/
.vscode/
*.swp

# Environment
.env.local

# Build
/dist/
`

var echoHandlerTemplate = `package main

import (
	"github.com/labstack/echo/v4"
)

// Custom handlers for your application

func registerCustomRoutes(e *echo.Echo) {
	// Add your custom routes here
	e.GET("/", func(c echo.Context) error {
		return c.JSON(200, map[string]string{
			"message": "Welcome to Kayan!",
		})
	})
}
`
