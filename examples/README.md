# Kayan Examples

This directory contains examples of how to extend Kayan with custom functionality and handle various user schema patterns.

## Examples

### 1. Flexible Generic IDs ([flexible_id_uint64](./flexible_id_uint64))
Explicitly demonstrates how to use `uint64` as the primary key for identities and sessions, moving away from the default UUIDs.

### 2. Companion Profile Pattern ([companion_profile](./companion_profile))
Demonstrates how to keep Kayan's auth data separate from your application's user profiles while keeping them in sync using post-registration hooks.

### 3. Typed Wrapper Pattern ([typed_wrapper](./typed_wrapper))
Shows how to wrap Kayan's dynamic `Traits` (JSON) field in a Go struct for type-safe access throughout your application.

### 4. Custom Storage Mapping ([custom_storage_mapping](./custom_storage_mapping))
Illustrates how to implement custom storage logic to perform dual-writes or map Kayan's models to existing legacy tables.

### 5. Full Custom Schema ([full_custom_schema](./full_custom_schema))
The ultimate flexibility: completely replace Kayan's database layout by implementing the `domain.Storage` interface to map models to entirely custom table structures.

### 6. MongoDB Storage ([custom_storage](./custom_storage))
Demonstrates how to implement a fully custom non-RDBMS storage backend using the official MongoDB driver.

## How to Run the Examples

Each example is a self-contained Go module. To run an example:

```bash
cd examples/[example_name]
go run main.go
```
