$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$apidiff = Join-Path (go env GOPATH) "bin\apidiff.exe"
if (-not (Test-Path $apidiff)) {
    throw "apidiff is not installed; see api-baseline/README.md"
}

$modules = @(
    @("core", "github.com/getkayan/kayan/core"),
    @("kayan-gorm", "github.com/getkayan/kayan/kayan-gorm"),
    @("kayan-ldap", "github.com/getkayan/kayan/kayan-ldap"),
    @("kayan-oidc-provider", "github.com/getkayan/kayan/kayan-oidc-provider"),
    @("kayan-redis", "github.com/getkayan/kayan/kayan-redis"),
    @("kayan-saml", "github.com/getkayan/kayan/kayan-saml"),
    @("kayan-scim", "github.com/getkayan/kayan/kayan-scim"),
    @("kayan-testing", "github.com/getkayan/kayan/kayan-testing")
)

$failed = $false
foreach ($entry in $modules) {
    $module = $entry[0]
    $importPath = $entry[1]
    $baseline = Join-Path $root "api-baseline\$module.api"
    Push-Location (Join-Path $root $module)
    try {
        $report = (& $apidiff -m -incompatible $baseline $importPath | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) {
            throw "apidiff failed for $module"
        }
    } finally {
        Pop-Location
    }
    if ($report) {
        Write-Error "Incompatible public API change in ${module}:`n$report" -ErrorAction Continue
        $failed = $true
    } else {
        Write-Host "${module}: compatible"
    }
}

if ($failed) { exit 1 }
