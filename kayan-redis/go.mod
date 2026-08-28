module github.com/getkayan/kayan/kayan-redis

go 1.25.5

require (
	github.com/alicebob/miniredis/v2 v2.37.0
	github.com/getkayan/kayan/core v0.0.0
	github.com/redis/go-redis/v9 v9.7.3
)

require (
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/go-webauthn/webauthn v0.11.2 // indirect
	github.com/go-webauthn/x v0.1.14 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.0 // indirect
	github.com/google/go-tpm v0.9.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/yuin/gopher-lua v1.1.1 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
)

replace github.com/getkayan/kayan/core => ../core
