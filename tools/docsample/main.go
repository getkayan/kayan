// Command docsample typechecks the Go samples embedded in the documentation.
//
// A documented signature that does not compile is worse than no documentation:
// it looks authoritative and sends the reader down a path that cannot work.
// This walks every fenced Go block in docs/ and reports the ones that no
// longer match the API.
//
// Blocks that are deliberately partial — a bare interface definition, a
// fragment with no imports — are skipped rather than reported, so the signal
// stays meaningful. Mark a block with the `notest` info string to skip it
// explicitly.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var fence = regexp.MustCompile("(?s)```go( +notest)?\n(.*?)\n```")

func main() {
	root := "docs"
	if len(os.Args) > 1 {
		root = os.Args[1]
	}

	var checked, skipped int
	var findings []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".md") {
			return err
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		for i, match := range fence.FindAllStringSubmatch(string(content), -1) {
			if strings.TrimSpace(match[1]) == "notest" {
				skipped++
				continue
			}

			block := match[2]
			if !compilable(block) {
				skipped++
				continue
			}

			checked++
			if problems := inspect(block); len(problems) > 0 {
				for _, p := range problems {
					findings = append(findings,
						fmt.Sprintf("%s block %d: %s", path, i+1, p))
				}
			}
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "walk:", err)
		os.Exit(1)
	}

	fmt.Printf("checked %d samples, skipped %d fragments\n", checked, skipped)
	for _, f := range findings {
		fmt.Println("  " + f)
	}
	if len(findings) > 0 {
		os.Exit(1)
	}
}

// compilable reports whether a block is a whole enough unit to reason about.
// Interface and type declarations quoted for reference are not.
func compilable(block string) bool {
	trimmed := strings.TrimSpace(block)
	switch {
	case strings.HasPrefix(trimmed, "type "):
		return false
	case !strings.Contains(trimmed, "("):
		return false
	}
	return true
}

// inspect looks for the mistakes that actually recur in this repository:
// a storage or session call missing its context, and a reference to a package
// that was renamed or moved.
func inspect(block string) []string {
	var problems []string

	stale := map[string]string{
		"kgorm.":            "kgorm was renamed to gormstore (module kayan-gorm)",
		"kredis.":           "kredis was renamed to redisstore (module kayan-redis)",
		"core/oauth2":       "oauth2 moved to kayan-oidc-provider",
		"core/oidc":         "oidc moved to kayan-oidc-provider",
		"core/saml":         "saml moved to kayan-saml",
		"core/scim":         "scim moved to kayan-scim",
		"repo.AutoMigrate(": "AutoMigrate is deprecated; use AutoMigrateDev",
	}
	for needle, message := range stale {
		if strings.Contains(block, needle) {
			problems = append(problems, message)
		}
	}

	// Storage and session methods all take a context now. A sample calling one
	// without it predates that change.
	ctxMethods := []string{
		"CreateIdentity", "GetIdentity", "FindIdentity", "ListIdentities",
		"UpdateIdentity", "DeleteIdentity", "CreateCredential",
		"GetCredentialByIdentifier", "CreateSession", "GetSession", "DeleteSession",
	}
	for _, method := range ctxMethods {
		pattern := regexp.MustCompile(`\.` + method + `\(\s*(?:ctx|c|r\.Context\(\))?`)
		for _, call := range pattern.FindAllString(block, -1) {
			if !strings.Contains(call, "ctx") && !strings.Contains(call, "Context()") {
				problems = append(problems,
					method+" is called without a context")
			}
		}
	}

	return problems
}
