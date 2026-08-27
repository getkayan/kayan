#!/usr/bin/env bash
# Run the integration-tagged tests in the current module and fail if none ran.
#
# `go test -run <pattern>` exits 0 when the pattern matches nothing, so a job
# that pins an exact test name reports success after executing no tests at all.
# Every integration test here needs a service container, so a silent skip looks
# exactly like a passing run: green CI, nothing exercised.
#
# This runs the whole integration-tagged set rather than one pinned name, then
# asserts at least one test actually started.
set -euo pipefail

# Only tests whose name matches this pattern count toward the floor. Building
# with -tags=integration also compiles the ordinary tests in the package, so
# counting every test that ran would stay green even if the integration test
# itself disappeared.
name_pattern="${INTEGRATION_TEST_PATTERN:-Integration|RealRedis|VersionedMigration}"
min_tests="${MIN_INTEGRATION_TESTS:-1}"
# CI always runs with the race detector. It needs cgo, so leave an override for
# local runs on machines without a C toolchain.
race_flag="-race"
if [ "${INTEGRATION_RACE:-1}" = "0" ]; then
  race_flag=""
fi

output="$(mktemp)"
trap 'rm -f "${output}"' EXIT

status=0
go test ${race_flag} -count=1 -tags=integration -json ./... >"${output}" 2>&1 || status=$?

# One "run" action is emitted per test and per subtest; count only top-level
# tests so a change in subtest structure does not move the floor.
ran="$(grep '"Action":"run","Package":"[^"]*","Test":"[^/"]*"}' "${output}" 2>/dev/null \
  | grep -cE "\"Test\":\"[A-Za-z0-9_]*(${name_pattern})" || true)"
ran="${ran:-0}"

# Surface the human-readable log regardless of outcome.
grep '"Action":"output"' "${output}" \
  | sed -E 's/.*,"Output":"//; s/"}$//' \
  | sed -E 's/\\n$//; s/\\t/\t/g; s/\\"/"/g' || true

if [ "${status}" -ne 0 ]; then
  echo "integration tests failed (exit ${status})" >&2
  exit "${status}"
fi

if [ "${ran}" -lt "${min_tests}" ]; then
  echo "ERROR: ${ran} integration test(s) ran, expected at least ${min_tests}." >&2
  echo "A build tag, a -run filter, or a skipped package is hiding them." >&2
  exit 1
fi

echo "integration tests passed: ${ran} test(s) ran"
