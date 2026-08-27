#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
status=0
modules=(
  "core|github.com/getkayan/kayan/core"
  "kayan-gorm|github.com/getkayan/kayan/kayan-gorm"
  "kayan-ldap|github.com/getkayan/kayan/kayan-ldap"
  "kayan-observability|github.com/getkayan/kayan/kayan-observability"
  "kayan-oidc-provider|github.com/getkayan/kayan/kayan-oidc-provider"
  "kayan-redis|github.com/getkayan/kayan/kayan-redis"
  "kayan-saml|github.com/getkayan/kayan/kayan-saml"
  "kayan-scim|github.com/getkayan/kayan/kayan-scim"
  "kayan-testing|github.com/getkayan/kayan/kayan-testing"
)

for spec in "${modules[@]}"; do
  module="${spec%%|*}"
  import_path="${spec#*|}"
  baseline="${root}/api-baseline/${module}.api"
  report="$(cd "${root}/${module}" && apidiff -m -incompatible "${baseline}" "${import_path}")"
  if [[ -n "${report}" ]]; then
    echo "ERROR: incompatible public API change in ${module}:"
    echo "${report}"
    status=1
  else
    echo "${module}: compatible"
  fi
done

exit "${status}"
