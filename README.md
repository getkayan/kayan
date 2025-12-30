# Kayan

Kayan is a headless authentication service built with Go and Echo. It is designed for high extensibility and flexibility.

## Prerequisites

- Go 1.19 or higher
- (Optional) PostgreSQL or MySQL if not using SQLite

## How to Run

### 1. Configure Environment Variables

Create a `.env` file or set the following environment variables:

- `PORT`: Server port (default: 8080)
- `DB_TYPE`: `sqlite`, `postgres`, or `mysql` (default: `sqlite`)
- `DSN`: Database connection string (default: `kayan.db` for sqlite)
- `LOG_LEVEL`: `debug`, `info`, `warn`, `error` (default: `info`)

### 2. Install Dependencies

```bash
go mod download
```

### 3. Run the Server

```bash
go run cmd/kayan/main.go
```

The server will start at `http://localhost:8080`.

## API Documentation

The API follows a standard RESTful pattern.

- `POST /api/v1/registration`: Register a new user.
- `POST /api/v1/login`: Login and receive a session token.
- `GET /api/v1/whoami`: Get information about the current authenticated user (requires `Authorization` header).

## Running Tests

To run the full test suite:

```bash
go test ./...
```
