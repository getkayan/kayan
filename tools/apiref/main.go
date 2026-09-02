// Command apiref generates the exhaustive Go API index in docs/reference.
//
// The hand-written reference explains behavior and security contracts. This
// command supplies the mechanical half: every exported declaration in every
// public Kayan package, linked to its canonical pkg.go.dev entry. Keeping that
// list generated prevents a new API from silently outrunning the documentation.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type moduleSpec struct {
	dir        string
	importPath string
	guide      string
}

var modules = []moduleSpec{
	{dir: "core", importPath: "github.com/getkayan/kayan/core", guide: "core.md"},
	{dir: "kayan-gorm", importPath: "github.com/getkayan/kayan/kayan-gorm", guide: "adapters.md"},
	{dir: "kayan-ldap", importPath: "github.com/getkayan/kayan/kayan-ldap", guide: "adapters.md"},
	{dir: "kayan-observability", importPath: "github.com/getkayan/kayan/kayan-observability", guide: "observability.md"},
	{dir: "kayan-oidc-provider", importPath: "github.com/getkayan/kayan/kayan-oidc-provider", guide: "oidc-provider.md"},
	{dir: "kayan-redis", importPath: "github.com/getkayan/kayan/kayan-redis", guide: "adapters.md"},
	{dir: "kayan-saml", importPath: "github.com/getkayan/kayan/kayan-saml", guide: "saml.md"},
	{dir: "kayan-scim", importPath: "github.com/getkayan/kayan/kayan-scim", guide: "scim.md"},
	{dir: "kayan-testing", importPath: "github.com/getkayan/kayan/kayan-testing", guide: "adapters.md"},
}

type symbol struct {
	name    string
	kind    string
	anchor  string
	summary string
}

type packageAPI struct {
	importPath string
	guide      string
	summary    string
	symbols    []symbol
}

func main() {
	root := flag.String("root", ".", "repository root")
	out := flag.String("out", "docs/reference/go-api.md", "output path, relative to root")
	check := flag.Bool("check", false, "fail when the committed index is stale")
	flag.Parse()

	packages, err := discover(*root)
	if err != nil {
		fatal(err)
	}
	generated := render(packages)
	outPath := filepath.Join(*root, filepath.FromSlash(*out))

	if *check {
		current, err := os.ReadFile(outPath)
		if err != nil {
			fatal(fmt.Errorf("read API index: %w", err))
		}
		if !bytes.Equal(current, generated) {
			fatal(fmt.Errorf("%s is stale; run cd tools/apiref && GOWORK=off go run . -root ../..", filepath.ToSlash(*out)))
		}
		fmt.Printf("API reference covers %d packages and %d exported symbols\n", len(packages), symbolCount(packages))
		return
	}

	if err := os.WriteFile(outPath, generated, 0o644); err != nil {
		fatal(fmt.Errorf("write API index: %w", err))
	}
	fmt.Printf("wrote %s with %d packages and %d exported symbols\n", filepath.ToSlash(*out), len(packages), symbolCount(packages))
}

func discover(root string) ([]packageAPI, error) {
	var packages []packageAPI
	for _, module := range modules {
		moduleRoot := filepath.Join(root, module.dir)
		err := filepath.WalkDir(moduleRoot, func(dir string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !entry.IsDir() {
				return nil
			}
			if dir != moduleRoot {
				name := entry.Name()
				if strings.HasPrefix(name, ".") || name == "testdata" {
					return filepath.SkipDir
				}
			}

			pkg, ok, err := parsePackage(dir)
			if err != nil {
				return err
			}
			if !ok {
				return nil
			}

			rel, err := filepath.Rel(moduleRoot, dir)
			if err != nil {
				return err
			}
			importPath := module.importPath
			if rel != "." {
				importPath += "/" + filepath.ToSlash(rel)
			}
			pkg.importPath = importPath
			pkg.guide = module.guide
			packages = append(packages, pkg)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("scan %s: %w", module.dir, err)
		}
	}

	sort.Slice(packages, func(i, j int) bool { return packages[i].importPath < packages[j].importPath })
	return packages, nil
}

func parsePackage(dir string) (packageAPI, bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return packageAPI{}, false, err
	}

	fset := token.NewFileSet()
	var files []*ast.File
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ParseComments)
		if err != nil {
			return packageAPI{}, false, fmt.Errorf("parse %s: %w", filepath.Join(dir, name), err)
		}
		if file.Name.Name == "main" {
			continue
		}
		files = append(files, file)
	}
	if len(files) == 0 {
		return packageAPI{}, false, nil
	}

	api := packageAPI{}
	for _, file := range files {
		if api.summary == "" && file.Doc != nil {
			api.summary = firstSentence(file.Doc.Text())
		}
		for _, decl := range file.Decls {
			switch value := decl.(type) {
			case *ast.GenDecl:
				collectGenDecl(&api, value)
			case *ast.FuncDecl:
				collectFunc(&api, value)
			}
		}
	}

	sort.Slice(api.symbols, func(i, j int) bool {
		if api.symbols[i].name == api.symbols[j].name {
			return api.symbols[i].kind < api.symbols[j].kind
		}
		return api.symbols[i].name < api.symbols[j].name
	})
	return api, true, nil
}

func collectGenDecl(api *packageAPI, decl *ast.GenDecl) {
	for _, spec := range decl.Specs {
		switch value := spec.(type) {
		case *ast.TypeSpec:
			if !value.Name.IsExported() {
				continue
			}
			doc := commentText(value.Doc, decl.Doc)
			api.symbols = append(api.symbols, symbol{name: value.Name.Name, kind: "type", anchor: value.Name.Name, summary: firstSentence(doc)})
		case *ast.ValueSpec:
			kind := strings.ToLower(decl.Tok.String())
			doc := commentText(value.Doc, decl.Doc)
			for _, name := range value.Names {
				if name.IsExported() {
					api.symbols = append(api.symbols, symbol{name: name.Name, kind: kind, anchor: name.Name, summary: firstSentence(doc)})
				}
			}
		}
	}
}

func collectFunc(api *packageAPI, decl *ast.FuncDecl) {
	if !decl.Name.IsExported() {
		return
	}
	name := decl.Name.Name
	anchor := name
	kind := "func"
	if decl.Recv != nil && len(decl.Recv.List) > 0 {
		receiver := receiverName(decl.Recv.List[0].Type)
		if receiver == "" {
			return
		}
		name = receiver + "." + name
		anchor = name
		kind = "method"
	}
	api.symbols = append(api.symbols, symbol{name: name, kind: kind, anchor: anchor, summary: firstSentence(commentText(decl.Doc))})
}

func receiverName(expr ast.Expr) string {
	switch value := expr.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.StarExpr:
		return receiverName(value.X)
	case *ast.IndexExpr:
		return receiverName(value.X)
	case *ast.IndexListExpr:
		return receiverName(value.X)
	default:
		return ""
	}
}

func commentText(groups ...*ast.CommentGroup) string {
	for _, group := range groups {
		if group != nil {
			return group.Text()
		}
	}
	return ""
}

func firstSentence(text string) string {
	text = strings.Join(strings.Fields(text), " ")
	if text == "" {
		return ""
	}
	if at := strings.Index(text, ". "); at >= 0 {
		return text[:at+1]
	}
	return strings.TrimSuffix(text, ".") + "."
}

func render(packages []packageAPI) []byte {
	var out strings.Builder
	out.WriteString("# Go API index\n\n")
	out.WriteString("> Generated from the exported Go declarations. Do not edit this file by hand; run\n")
	out.WriteString("> `cd tools/apiref && GOWORK=off go run . -root ../..` after changing the public API.\n\n")
	out.WriteString("This is the exhaustive declaration index for Kayan's public Go API. Each entry links\n")
	out.WriteString("to its canonical declaration and package documentation on pkg.go.dev. The linked\n")
	out.WriteString("guide beside each package explains lifecycle, security behavior, errors, and usage.\n")
	out.WriteString("Exported fields and interface methods are shown on the linked type declaration.\n\n")
	out.WriteString(fmt.Sprintf("**Coverage:** %d packages, %d exported symbols.\n\n", len(packages), symbolCount(packages)))
	out.WriteString("## Packages\n\n")
	for _, pkg := range packages {
		out.WriteString(fmt.Sprintf("- [`%s`](#%s)\n", pkg.importPath, markdownID(pkg.importPath)))
	}

	for _, pkg := range packages {
		packageURL := "https://pkg.go.dev/" + pkg.importPath
		out.WriteString(fmt.Sprintf("\n## `%s`\n\n", pkg.importPath))
		if pkg.summary != "" {
			out.WriteString(pkg.summary + "\n\n")
		}
		out.WriteString(fmt.Sprintf("[Package documentation](%s) | [Behavioral guide](./%s)\n\n", packageURL, pkg.guide))
		for _, item := range pkg.symbols {
			out.WriteString(fmt.Sprintf("- [`%s %s`](%s#%s)", item.kind, item.name, packageURL, item.anchor))
			if item.summary != "" {
				out.WriteString(" - " + item.summary)
			}
			out.WriteByte('\n')
		}
	}
	return []byte(out.String())
}

func markdownID(value string) string {
	value = strings.ToLower(value)
	var out strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out.WriteRune(r)
		case r == '-' || r == '_':
			out.WriteRune(r)
		case r == ' ':
			out.WriteByte('-')
		}
	}
	return strings.Trim(out.String(), "-")
}

func symbolCount(packages []packageAPI) int {
	total := 0
	for _, pkg := range packages {
		total += len(pkg.symbols)
	}
	return total
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "apiref:", err)
	os.Exit(1)
}
