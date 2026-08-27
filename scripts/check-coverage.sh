#!/usr/bin/env bash
# Fail when a package drops below its recorded coverage floor.
#
# Coverage percentages on their own are not a goal, and a repository-wide
# average hides the cases that matter: core/admin gates every privileged
# operation and sat at 11.3%, core/audit is the record an incident is
# reconstructed from and sat at 13.0%. Both were raised deliberately. This
# stops them sliding back without anyone noticing.
#
# Floors live in coverage-floors.txt. A package with no floor is reported but
# does not fail the build, so adding a package is not blocked -- though the
# report says plainly that it is unguarded.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
floors_file="${root}/coverage-floors.txt"

if [ ! -f "${floors_file}" ]; then
  echo "ERROR: ${floors_file} not found" >&2
  exit 1
fi

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

measured="$(mktemp)"
trap 'rm -f "${measured}"' EXIT

for module in "${modules[@]}"; do
  (
    cd "${root}/${module}"
    # Package lines look like:
    #   ok  <import path>  0.5s  coverage: 71.7% of statements
    go test -cover ./... 2>/dev/null \
      | grep -E '^ok[[:space:]]' \
      | grep 'coverage:' \
      | sed 's|github.com/getkayan/kayan/||' \
      | awk '{
          pkg = $2
          for (i = 1; i <= NF; i++) {
            if ($i == "coverage:") {
              pct = $(i + 1)
              sub(/%$/, "", pct)
              print pkg, pct
            }
          }
        }'
  ) >>"${measured}"
done

status=0
unguarded=0

while read -r pkg pct; do
  [ -z "${pkg}" ] && continue

  floor="$(awk -v p="${pkg}" '$1 == p { print $2 }' "${floors_file}" | head -n 1)"

  if [ -z "${floor}" ]; then
    echo "note:  ${pkg} at ${pct}% has no floor recorded"
    unguarded=$((unguarded + 1))
    continue
  fi

  # Integer comparison on the whole-percent part is enough: floors are set
  # below the measured value, so fractional drift never decides the outcome.
  whole="${pct%%.*}"
  if [ "${whole}" -lt "${floor}" ]; then
    echo "ERROR: ${pkg} coverage ${pct}% is below its floor of ${floor}%"
    status=1
  else
    echo "ok:    ${pkg} ${pct}% (floor ${floor}%)"
  fi
done <"${measured}"

if [ "${unguarded}" -gt 0 ]; then
  echo
  echo "${unguarded} package(s) have no floor. Add them to coverage-floors.txt."
fi

if [ "${status}" -ne 0 ]; then
  echo
  echo "Coverage fell below a recorded floor. Either restore the tests, or lower"
  echo "the floor deliberately in its own commit with a reason."
fi

exit "${status}"
