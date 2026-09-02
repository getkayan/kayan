package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestParsePackageCollectsPublicSurface(t *testing.T) {
	source := `// Package sample demonstrates the scanner.
package sample

const Public = "value"
const private = "value"

type Service struct {
	Name string
	hidden string
}

func NewService() *Service { return &Service{} }
func (s *Service) Start() {}
func (s *Service) stop() {}
`
	file, err := parser.ParseFile(token.NewFileSet(), "sample.go", source, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}

	api := packageAPI{}
	for _, decl := range file.Decls {
		switch value := decl.(type) {
		case *ast.GenDecl:
			collectGenDecl(&api, value)
		case *ast.FuncDecl:
			collectFunc(&api, value)
		}
	}

	var names []string
	for _, item := range api.symbols {
		names = append(names, item.name)
	}
	joined := strings.Join(names, ",")
	for _, want := range []string{"Public", "Service", "NewService", "Service.Start"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q from %q", want, joined)
		}
	}
	for _, unwanted := range []string{"private", "hidden", "stop"} {
		if strings.Contains(joined, unwanted) {
			t.Fatalf("unexpected private symbol %q in %q", unwanted, joined)
		}
	}
}

func TestFirstSentence(t *testing.T) {
	if got := firstSentence("First line\ncontinues. Second sentence."); got != "First line continues." {
		t.Fatalf("firstSentence() = %q", got)
	}
}

func TestMarkdownIDMatchesGitHubHeadingSlug(t *testing.T) {
	want := "githubcomgetkayankayankayan-oidc-provideroauth2"
	if got := markdownID("github.com/getkayan/kayan/kayan-oidc-provider/oauth2"); got != want {
		t.Fatalf("markdownID() = %q, want %q", got, want)
	}
}
