module example/api-key

go 1.25.5

require (
	github.com/getkayan/kayan/core v0.3.0
	github.com/google/uuid v1.6.0
)

require (
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/go-webauthn/webauthn v0.11.2 // indirect
	github.com/go-webauthn/x v0.1.14 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.0 // indirect
	github.com/google/go-tpm v0.9.1 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
)

replace github.com/getkayan/kayan/core => ../../../core

// Run: go mod tidy

require github.com/getkayan/kayan/kayan-testing v0.3.0

replace github.com/getkayan/kayan/kayan-testing => ../../../kayan-testing
