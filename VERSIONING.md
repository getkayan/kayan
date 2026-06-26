# Versioning and Support

Kayan follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## Public API Surface

The compatibility contract for a stable release covers:

- exported packages and symbols in `core/`
- exported packages and symbols in `kgorm/` and `kredis/`
- documented commands and flags in `cmd/kayan-cli/`
- documented behavior in the main guides under `docs/`

The following are not strict compatibility contracts:

- internal packages, unexported symbols, and test helpers
- implementation details not described in docs or godoc
- example applications under `examples/`
- generated site output under `site/`

## SemVer Interpretation

- Patch releases (`1.2.3` -> `1.2.4`) are for bug fixes, documentation fixes, security fixes, and low-risk internal improvements.
- Minor releases (`1.2.0` -> `1.3.0`) may add new packages, options, constructors, strategies, and adapters in a backward-compatible way.
- Major releases (`1.x` -> `2.0`) may remove deprecated APIs or make breaking behavioral changes.

## Stability Levels

Kayan uses these stability levels:

- Stable: default for released, documented APIs unless explicitly marked otherwise.
- Experimental: features or packages called out as experimental in docs, comments, or release notes. Experimental APIs may change in a minor release.
- Deprecated: supported for the current major version, but scheduled for removal in a future major version. See [DEPRECATION.md](./DEPRECATION.md).

## Support Policy

- The latest release on the current stable major version is the primary supported target.
- Critical bug fixes and security fixes are applied to the latest release first.
- Recent minor releases on the current major may receive selected backports when practical, but the latest release remains the recommended upgrade target.
- Security reporting and coordinated disclosure follow [SECURITY.md](./SECURITY.md).

## Compatibility Expectations

- Public APIs are not removed in a patch or minor release unless a security issue requires immediate action.
- Deprecated APIs remain available for the rest of the current major version unless a security issue requires earlier removal.
- New behavior that could affect existing integrations should be documented in [CHANGELOG.md](./CHANGELOG.md).

## For Contributors

When changing a public surface:

1. Decide whether the change is patch, minor, or major according to this policy.
2. Update [CHANGELOG.md](./CHANGELOG.md).
3. Mark deprecations explicitly and document the replacement path.
4. Update guides in `docs/` when behavior changes.