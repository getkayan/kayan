# --help

A Kayan-powered authentication service.

## Quick Start

```bash
go mod tidy
go run main.go
```

## API Endpoints

- POST /api/v1/registration - Register new user
- POST /api/v1/login - Login
- GET /api/v1/whoami - Get current user
- GET /api/v1/me - Protected route example

## Environment

Copy .env to configure:
- PORT - Server port (default: 8080)
- DATABASE_URL - Database connection string
