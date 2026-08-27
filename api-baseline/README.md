# Public API baseline

The `.api` files are semantic Go export-data snapshots for Kayan's public
modules. CI compares the current tree with these snapshots and rejects removed
symbols, changed signatures, narrowed interfaces, and other source-incompatible
changes.

The baseline starts at the reviewed pre-1.0 API freeze. Historical `v0.1.0`
tags predate the multi-module architecture and are documented separately in
[`docs/reference/pre-1.0-migration.md`](../docs/reference/pre-1.0-migration.md).

Run the check on Windows with:

```powershell
go install golang.org/x/exp/cmd/apidiff@v0.0.0-20260709172345-9ea1abe57597
./scripts/check-api.ps1
```

Baseline updates are never an automatic fix for a failed check. They require an
intentional SemVer decision, changelog and migration documentation, and reviewer
approval. Regenerate one snapshot from its module directory with:

```text
apidiff -m -w ../api-baseline/<module>.api <module-import-path>
```

This checker covers source compatibility. Behavioral contracts, persistence
formats, command flags, and protocol behavior still require tests and review.
