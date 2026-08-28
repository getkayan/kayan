#!/usr/bin/env bash
#
# Verify every module resolves on its own, the way CI does.
#
# go.work is gitignored, so a developer's machine builds in workspace mode and
# CI builds each module from its own go.mod. The two disagree: a dependency
# reachable through go.work.sum satisfies a local build while the module's own
# go.sum is missing the entry, and CI is the first thing to notice.
#
# That is not hypothetical. kayan-oidc-provider, kayan-saml, and kayan-testing
# all imported core, which imports golang.org/x/crypto, without recording it --
# so those three modules could not build in CI at all while every local check
# passed, for long enough that nobody connected the two.
#
# Run this before pushing. GOWORK=off is the whole point of it.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
status=0

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

for module in "${modules[@]}"; do
  printf '%-22s ' "${module}"
  if output="$(cd "${root}/${module}" && GOWORK=off go build ./... 2>&1)"; then
    echo "ok"
  else
    echo "FAILED"
    echo "${output}" | sed 's/^/    /'
    status=1
  fi
done

if [ "${status}" -ne 0 ]; then
  echo
  echo "A module cannot build from its own go.mod. Run, in that module:"
  echo "    GOWORK=off go mod tidy"
fi

exit "${status}"
