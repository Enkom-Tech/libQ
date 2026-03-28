#!/usr/bin/env pwsh
# PowerShell script for running targeted test coverage analysis

param (
    [string]$Crate = "",
    [switch]$ShowReport,
    [string]$OutputDir = "coverage",
    [string]$OutputFormat = "Html",
    [switch]$IgnoreTests,
    [switch]$IgnorePanics,
    [string]$LineThreshold = "95",
    [string]$Toolchain = "stable"
)

$ShowReport = if ($PSBoundParameters.ContainsKey('ShowReport')) { $ShowReport } else { $true }
$IgnoreTests = if ($PSBoundParameters.ContainsKey('IgnoreTests')) { $IgnoreTests } else { $true }
$IgnorePanics = if ($PSBoundParameters.ContainsKey('IgnorePanics')) { $IgnorePanics } else { $true }

$ScriptRoot = $PSScriptRoot
if ([string]::IsNullOrEmpty($ScriptRoot)) { $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }

if ($OutputFormat -eq "Html") {
    $OutputFormat = "Html,Xml"
} elseif ($OutputFormat -like "*Html*" -and $OutputFormat -notlike "*Xml*" -and $OutputFormat -notlike "*Cobertura*") {
    $OutputFormat = "$OutputFormat,Xml"
}

if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
    Write-Host "Created directory: $OutputDir"
}

$cmd = if ($Toolchain -eq "stable") { "cargo tarpaulin" } else { "cargo +$Toolchain tarpaulin" }

if ($Crate -ne "") {
    $cmd += " --packages $Crate"
    if ($Crate -eq "lib-q-core") {
        $cmd += " --features std,rand"
    } elseif ($Crate -eq "lib-q-fn-dsa") {
        $cmd += " --features std,rand"
    } elseif ($Crate -eq "lib-q") {
        $cmd += " --features all-algorithms"
    } elseif ($Crate -eq "lib-q-cb-kem") {
        $cmd += " --features std,rand,getrandom,sha3-hash,alloc,zeroize,cbkem348864"
    }
}

if ($IgnoreTests) { $cmd += " --ignore-tests" }
if ($IgnorePanics) { $cmd += " --ignore-panics" }

$cmd += ' --exclude-files "target/*" --exclude-files "benches/*" --exclude-files "examples/*"'

$cmd += " --out $OutputFormat --output-dir $OutputDir"

Write-Host "Running: $cmd"
Invoke-Expression $cmd

if ($LASTEXITCODE -ne 0) {
    Write-Host "cargo tarpaulin exited with status $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}

if ($ShowReport) {
    $idx = Join-Path $OutputDir "index.html"
    $rep = Join-Path $OutputDir "tarpaulin-report.html"
    if (Test-Path -LiteralPath $idx) {
        Write-Host "Opening coverage report..."
        Start-Process $idx
    } elseif (Test-Path -LiteralPath $rep) {
        Write-Host "Opening coverage report..."
        Start-Process $rep
    }
}

$extract = Join-Path $ScriptRoot "extract-coverage-percent.ps1"
if (-not (Test-Path -LiteralPath $extract)) {
    Write-Host "Missing $extract" -ForegroundColor Red
    exit 1
}

$out = & $extract -OutputDir $OutputDir
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($out)) {
    Write-Host "Could not determine coverage percentage." -ForegroundColor Red
    Get-ChildItem -LiteralPath $OutputDir -ErrorAction SilentlyContinue | Format-Table -AutoSize
    exit 1
}

$coverage = [double]$out
if ($env:GITHUB_ENV) {
    Add-Content -LiteralPath $env:GITHUB_ENV -Value "COVERAGE_PERCENT=$coverage"
}

if ($coverage -lt [double]$LineThreshold) {
    Write-Host "Coverage is $coverage%, which is below the $LineThreshold% threshold." -ForegroundColor Red
    exit 1
}

Write-Host "Coverage is $coverage%, which meets or exceeds the $LineThreshold% threshold." -ForegroundColor Green
exit 0
