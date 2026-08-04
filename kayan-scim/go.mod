module github.com/getkayan/kayan/kayan-scim

go 1.25.5

require (
	github.com/getkayan/kayan/core v0.0.0
	gorm.io/gorm v1.31.1
)

require (
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	golang.org/x/text v0.32.0 // indirect
)

replace github.com/getkayan/kayan/core => ../core
