# Kayan Examples

This directory contains examples of how to extend Kayan with custom functionality.

## Examples

### 1. Custom Storage ([custom_storage](./custom_storage))
Demonstrates how to implement the `domain.Storage` interface and register it with the `persistence` registry. This allows you to use Kayan with any database (e.g., MongoDB, Redis, In-Memory) without modifying the core codebase.

## How to Run the Examples

Each example is a self-contained Go application.

```bash
cd examples/custom_storage
go run main.go
```
