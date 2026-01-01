# Kayan Examples

This directory contains examples of how to extend Kayan with custom functionality and handle various user schema patterns.

## Examples

### 1. Flexible Generic IDs
Kayan no longer enforces `uuid.UUID`. You can use any type for primary keys.

- **[Snowflake IDs (int64)](./flexible_id_snowflake)**: Demonstrates integration with a distributed ID generator (Snowflake).
- **[Auto-Incremental IDs (uint)](./flexible_id_autoincrement)**: Shows how to delegate ID generation to the database.
- **[Flexible uint64](./flexible_id_uint64)**: A generic example using `uint64`.

### 2. Standalone Schema Patterns

- **[Companion Profile Pattern](./companion_profile)**: Keep Auth (Kayan) and Business Data (App) 100% separate.
- **[Typed Wrapper Pattern](./typed_wrapper)**: Wrap Kayan's dynamic `Traits` (JSON) field in a Go struct.
- **[Custom Storage Mapping](./custom_storage_mapping)**: Implement custom storage logic for dual-writes or mapping to legacy tables.
- **[Full Custom Schema](./full_custom_schema)**: Completely replace Kayan's DB layout.
- **[MongoDB Storage](./custom_storage)**: Use a non-RDBMS backend (MongoDB).

## How to Run the Examples

Each example is a self-contained Go module. To run an example:

```bash
cd examples/[example_name]
go run main.go
```
