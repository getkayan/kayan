# Contributing to Kayan

Thank you for your interest in contributing to Kayan! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Architectural Guardrails

Kayan is a multi-module Go workspace with strict package-boundary rules. Before making structural or cross-package changes, read [AGENTS.md](AGENTS.md) for:

- module-level build and test commands
- dependency direction rules
- adapter versus core package boundaries
- testing and architecture expectations

## Getting Started

### Prerequisites

- Go 1.21 or later
- Git
- A database (SQLite for development, PostgreSQL recommended for production)

### Development Setup

1. **Fork and clone the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/kayan.git
   cd kayan
   ```

2. **Understand the workspace layout**
   
   Kayan uses a Go workspace (`go.work`) with multiple modules. Always run Go commands from the module directory you are working in.

   Primary modules:

   - `core/` - main IAM library
   - `kayan-gorm/` - optional GORM storage adapter
   - `kayan-redis/` - optional Redis adapters
   - `cmd/kayan-cli/` - administrative CLI

   Do not run `go test ./...` from the repository root.

3. **Install dependencies**
   ```bash
   cd core && go mod download
   cd ../kayan-gorm && go mod download
   cd ../kayan-redis && go mod download
   cd ..
   ```

4. **Verify your setup**
   ```bash
   cd core && go test -race ./...
   cd ../kayan-gorm && go test -race ./...
   cd ../kayan-redis && go test -race ./...
   cd ..
   ```

5. **Optional: run a reference example**
   ```bash
   cd examples/01-password/backend
   go run .
   ```

### Integration Tests

Database integration tests are not yet present. The commands below describe the
planned PostgreSQL gate and must not be treated as an active test suite until
`kayan-gorm` contains `integration`-tagged tests and CI runs them against a real
PostgreSQL service.

1. **Start PostgreSQL locally**
   ```bash
   docker run --name kayan-pg ^
     -e POSTGRES_USER=kayan ^
     -e POSTGRES_PASSWORD=kayan ^
     -e POSTGRES_DB=kayan_test ^
     -p 5432:5432 ^
     postgres:15
   ```

2. **Set the database URL**
   ```bash
   set DATABASE_URL=postgres://kayan:kayan@localhost:5432/kayan_test?sslmode=disable
   ```

3. **Run integration tests from the `core/` module**
   ```bash
   cd kayan-gorm
   go test -race -tags=integration ./...
   ```

CI uses the same connection string and module-local command layout.

## How to Contribute

### Reporting Bugs

Before creating a bug report, please check existing issues to avoid duplicates.

When filing a bug report, include:
- A clear, descriptive title
- Steps to reproduce the issue
- Expected behavior vs actual behavior
- Go version, OS, and Kayan version
- Relevant logs or error messages

### Suggesting Features

We welcome feature requests! Please:
- Check existing issues/discussions first
- Clearly describe the use case
- Explain why this would benefit other users

### Pull Requests

1. **Create a branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Follow Go conventions and run `gofmt`
   - Add tests for new functionality
   - Update documentation as needed

3. **Run tests and linting**
   ```bash
   cd core
   go test -race -coverprofile=coverage.out -covermode=atomic ./...
   golangci-lint run

   cd ../kayan-gorm
   go test -race ./...

   cd ../kayan-redis
   go test -race ./...

   cd ../cmd/kayan-cli
   go build -o kayan-cli .
   ```

4. **Commit with clear messages**
   ```bash
   git commit -m "feat: add password policy validation"
   ```
   
   Follow [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` new features
   - `fix:` bug fixes
   - `docs:` documentation changes
   - `test:` adding/updating tests
   - `refactor:` code refactoring

5. **Push and create a PR**
   ```bash
   git push origin feature/your-feature-name
   ```

## Code Style

- Run `gofmt` on all Go files
- Keep functions focused and under 50 lines when possible
- Add comments for exported functions
- Use meaningful variable names

## Testing

- All new features should have tests
- Aim for >80% coverage on new code
- Unit tests should be run per module with `-race`
- Integration tests should use the `integration` build tag and run separately from unit tests
- Use table-driven tests where appropriate

## Documentation

- Update README.md for user-facing changes
- Add godoc comments for public APIs
- Include examples in the `examples/` directory for complex features

## Need Help?

- Open a [Discussion](https://github.com/getkayan/kayan/discussions)
- Check existing [Issues](https://github.com/getkayan/kayan/issues)

Thank you for contributing! 🎉
