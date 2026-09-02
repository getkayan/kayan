#!/usr/bin/env bash
#
# Verify a project outside this repository can actually import Kayan.
#
# check-modules.sh builds each module in place, where its own replace
# directives apply. A consumer gets neither: a replace is honoured only while
# its module is the main module, so an importing project resolves the require
# version from the proxy instead.
#
# That difference hid a total failure. Every module required
# core v0.0.0 -- a version never tagged -- so `go get` of any part of Kayan
# ended in "unknown revision core/v0.0.0" while every check here passed. The
# library was unconsumable and nothing said so.
#
# This builds a throwaway module with no replaces and imports the real
# published versions, which is the only arrangement that reproduces what a
# consumer sees.
#
# It needs the network and the tags to be pushed, so it validates the last
# release rather than the working tree. That is the point: releases are what
# consumers get.
set -euo pipefail

version="${1:-}"
if [ -z "${version}" ]; then
  version="$(git -C "$(dirname "${BASH_SOURCE[0]}")/.." tag --list 'core/v*' --sort=-v:refname | head -1)"
  version="${version#core/}"
fi
if [ -z "${version}" ]; then
  echo "ERROR: no core/v* tag to verify against" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT
cd "${work}"

go mod init kayan.test/consumable >/dev/null

cat > main.go <<'GO'
package main

import (
	"fmt"

	"github.com/getkayan/kayan/core/domain"
	_ "github.com/getkayan/kayan/kayan-gorm"
	_ "github.com/getkayan/kayan/kayan-ldap"
	_ "github.com/getkayan/kayan/kayan-observability/config"
	_ "github.com/getkayan/kayan/kayan-observability/logger"
	_ "github.com/getkayan/kayan/kayan-observability/telemetry"
	_ "github.com/getkayan/kayan/kayan-oidc-provider/gormstore"
	_ "github.com/getkayan/kayan/kayan-oidc-provider/oauth2"
	_ "github.com/getkayan/kayan/kayan-oidc-provider/oidc"
	_ "github.com/getkayan/kayan/kayan-redis"
	_ "github.com/getkayan/kayan/kayan-saml"
	_ "github.com/getkayan/kayan/kayan-scim"
	_ "github.com/getkayan/kayan/kayan-scim/gormstore"
	_ "github.com/getkayan/kayan/kayan-testing"
)

func main() {
	hasher := domain.NewBcryptHasher(0)
	hash, err := hasher.Hash("verification-secret")
	if err != nil {
		panic(err)
	}
	if !hasher.Compare("verification-secret", hash) || hasher.Compare("wrong", hash) {
		panic("the published core does not hash correctly")
	}
	fmt.Println("ok")
}
GO

modules=(
  core
  kayan-gorm
  kayan-ldap
  kayan-observability
  kayan-oidc-provider
  kayan-redis
  kayan-saml
  kayan-scim
  kayan-testing
)

echo "verifying consumers can import every Kayan module at ${version} with no replace directives"
for module in "${modules[@]}"; do
  echo "  resolving ${module}@${version}"
  if ! output="$(GOFLAGS=-mod=mod GOWORK=off go get "github.com/getkayan/kayan/${module}@${version}" 2>&1)"; then
    echo "ERROR: could not resolve ${module}@${version}:" >&2
    echo "${output}" >&2
    exit 1
  fi
done
GOFLAGS=-mod=mod GOWORK=off go mod tidy >/dev/null 2>&1

if ! output="$(GOWORK=off go run . 2>&1)"; then
  echo "ERROR: a project outside this repository cannot build against Kayan ${version}:" >&2
  echo "${output}" >&2
  echo >&2
  echo "Usually this means a module requires a version that was never tagged." >&2
  exit 1
fi

echo "every Kayan module at ${version} is consumable"
