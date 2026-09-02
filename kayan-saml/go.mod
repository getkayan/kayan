module github.com/getkayan/kayan/kayan-saml

go 1.25.5

require (
	github.com/beevik/etree v1.7.0
	github.com/getkayan/kayan/core v0.3.0
	github.com/russellhaering/goxmldsig v1.6.1
)

require (
	github.com/jonboulle/clockwork v0.5.0 // indirect
	golang.org/x/crypto v0.46.0 // indirect
)

replace github.com/getkayan/kayan/core => ../core
