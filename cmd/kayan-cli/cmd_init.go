package main

import (
	"fmt"
	"os"
)

// ---- Init & Generate Commands ----

func initCommand(args []string) error {
	projectName := "."
	if len(args) > 0 {
		projectName = args[0]
	}

	// Create project directory if needed
	if projectName != "." {
		// #nosec G301,G703 -- projectName is the explicit CLI destination and
		// generated source directories must remain traversable by collaborators.
		if err := os.MkdirAll(projectName, 0755); err != nil {
			return err
		}
	}

	// Determine module name
	moduleName := projectName
	if projectName == "." {
		// cwd, _ := os.Getwd() // simplified for now
		moduleName = "my-app"
	}

	// Generate go.mod
	goModContent := fmt.Sprintf("module %s\n\ngo 1.25\n\nrequire github.com/getkayan/kayan/core v1.0.0\n", moduleName)
	if err := writeFile(projectName+"/go.mod", goModContent); err != nil {
		return err
	}

	// Generate main.go
	mainContent := `package main

import (
	"fmt"

	"github.com/getkayan/kayan/core/identity"
)

// User is your application-owned schema. Kayan only requires GetID and SetID;
// it does not prescribe a database, ORM, table, or HTTP framework.
type User struct {
	ID    string
	Email string
}

func (u *User) GetID() any  { return u.ID }
func (u *User) SetID(id any) { u.ID = id.(string) }

var _ identity.FlowIdentity = (*User)(nil)

func main() {
	userFactory := func() any { return &User{} }
	fmt.Printf("Kayan identity factory ready: %T\n", userFactory())

	// Next: choose any storage implementation of core/domain contracts and any
	// transport layer. Optional official adapters are separate Kayan modules.
}
`
	if err := writeFile(projectName+"/main.go", mainContent); err != nil {
		return err
	}

	fmt.Printf("Initialized Kayan project in %s\n", projectName)
	return nil
}

func generateCommand(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: kayan-cli generate <subcommand>")
	}
	sub := args[0]
	if sub == "handler" {
		fmt.Println("Generating handlers... (stub)")
		return nil
	}
	return fmt.Errorf("unknown generate subcommand: %s", sub)
}

func writeFile(path, content string) error {
	// #nosec G306,G703 -- path is derived from the explicit init destination;
	// generated Go source is intentionally readable like normal source files.
	return os.WriteFile(path, []byte(content), 0644)
}
