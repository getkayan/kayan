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
	goModContent := fmt.Sprintf("module %s\n\ngo 1.25\n\nrequire github.com/getkayan/kayan v1.0.0\n", moduleName)
	if err := writeFile(projectName+"/go.mod", goModContent); err != nil {
		return err
	}

	// Generate main.go
	mainContent := `package main

import (
	"log"
	"net/http"
	"time"

	"github.com/getkayan/kayan/core/session"
	"github.com/getkayan/kayan/core/flow"
	"github.com/getkayan/kayan/kgorm"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	// 1. Database
	db, err := gorm.Open(sqlite.Open("app.db"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
	repo := kgorm.NewRepository(db)

	// 2. Kayan Setup
	login := flow.NewLoginManager(repo)
	sess := session.NewManager(session.NewHS256Strategy("secret-key", 24*time.Hour))

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Login endpoint"))
	})
	
	log.Println("Server starting on :8080")
	http.ListenAndServe(":8080", nil)
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
	return os.WriteFile(path, []byte(content), 0644)
}
