# Contributing to Kayan

Thank you for your interest in contributing to Kayan! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

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

2. **Install dependencies**
   ```bash
   go mod download
   ```

3. **Run tests**
   ```bash
   go test ./...
   ```

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
   go test ./...
   go vet ./...
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
- Integration tests go in `*_test.go` files
- Use table-driven tests where appropriate

## Documentation

- Update README.md for user-facing changes
- Add godoc comments for public APIs
- Include examples in the `examples/` directory for complex features

## Need Help?

- Open a [Discussion](https://github.com/getkayan/kayan/discussions)
- Check existing [Issues](https://github.com/getkayan/kayan/issues)

Thank you for contributing! 🎉
