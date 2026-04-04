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
$RepoRoot = Split-Path -Parent $ScriptRoot
Set-Location -LiteralPath $RepoRoot

function Get-TarpaulinIncludeFlags {
    param([Parameter(Mandatory)][string]$CrateName)
    $pin = Join-Path $ScriptRoot "print-tarpaulin-include-args.sh"
    $bash = Get-Command bash.exe -ErrorAction SilentlyContinue
    if ($null -eq $bash) { $bash = Get-Command bash -ErrorAction SilentlyContinue }
    if ($null -ne $bash -and (Test-Path -LiteralPath $pin)) {
        $bashExe = $bash.Path
        if ([string]::IsNullOrEmpty($bashExe)) { $bashExe = $bash.Source }
        $out = & $bashExe $pin $CrateName 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            Write-Host $out.Trim() -ForegroundColor Red
            exit 1
        }
        return $out.Trim()
    }
    $metaJson = cargo metadata --format-version 1 --no-deps 2>$null | Out-String
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($metaJson)) {
        Write-Host "cargo metadata failed (run from a workspace directory)" -ForegroundColor Red
        exit 1
    }
    $meta = $metaJson | ConvertFrom-Json
    $ws = $meta.workspace_root
    if ([string]::IsNullOrWhiteSpace($ws)) { $ws = (Get-Location).Path }
    $ws = (Resolve-Path -LiteralPath $ws).Path

    $prel = $null
    $exToml = [System.IO.Path]::Combine($ws, "examples", "Cargo.toml")
    if ($CrateName -eq "lib-q-examples" -and (Test-Path -LiteralPath $exToml)) {
        $prel = "examples"
    }
    elseif (Test-Path -LiteralPath ([System.IO.Path]::Combine($ws, $CrateName, "src")) -PathType Container) {
        $prel = ($CrateName -replace '\\', '/').TrimStart('./')
    }
    if ($null -eq $prel) {
        $pkgs = @($meta.packages | Where-Object { $_.name -eq $CrateName })
        if ($pkgs.Count -eq 0) {
            Write-Host "Unknown Cargo package: $CrateName (install Git Bash or use a path with src/)" -ForegroundColor Red
            exit 1
        }
        $manDir = Split-Path -Parent $pkgs[0].manifest_path
        $full = (Resolve-Path -LiteralPath $manDir).Path
        if ($full.Equals($ws, [StringComparison]::OrdinalIgnoreCase)) {
            Write-Host "Invalid package root at workspace root" -ForegroundColor Red
            exit 1
        }
        if (-not $full.StartsWith($ws, [StringComparison]::OrdinalIgnoreCase)) {
            Write-Host "Package outside workspace" -ForegroundColor Red
            exit 1
        }
        $prel = $full.Substring($ws.Length).TrimStart([char]'\', [char]'/') -replace '\\', '/'
    }
    $bs = $prel -replace '/', '\\'
    $prelFs = $prel -replace '/', [System.IO.Path]::DirectorySeparatorChar
    $srcAbs = [System.IO.Path]::Combine($ws, $prelFs, "src")
    if (Test-Path -LiteralPath $srcAbs -PathType Container) {
        return " --include-files ""$prel/src/*"" --include-files ""$prel/src/**"" --include-files ""$bs\src\*"""
    }
    return " --include-files ""$prel/*.rs"" --include-files ""$prel/**/*.rs"" --include-files ""$bs\*.rs"" --include-files ""$bs\**\*.rs"""
}

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
        $cmd += " --features std,rand,getrandom,alloc,zeroize,cbkem348864"
    } elseif ($Crate -eq "lib-q-kem") {
        $cmd += " --features std,alloc,ml-kem,hqc"
    } elseif ($Crate -eq "lib-q-ml-kem") {
        $cmd += " --features std,deterministic"
    }
}

if ($IgnoreTests) { $cmd += " --ignore-tests" }
if ($IgnorePanics) { $cmd += " --ignore-panics" }

$cmd += ' --exclude-files "target/' + '*' + '" --exclude-files "benches/' + '*' + '" --exclude-files "examples/' + '*' + '"'

if ($Crate -eq "lib-q-core") {
    $cmd += ' --exclude-files "lib-q-hash/' + '*' + '" --exclude-files "lib-q-hpke/' + '*' + '" --exclude-files "lib-q-intrinsics/' + '*' + '"'
    $cmd += ' --exclude-files "lib-q-k12/' + '*' + '" --exclude-files "lib-q-keccak/' + '*' + '" --exclude-files "lib-q-kem/' + '*' + '"'
    $cmd += ' --exclude-files "lib-q-ml-dsa/' + '*' + '" --exclude-files "lib-q-ml-kem/' + '*' + '" --exclude-files "lib-q-sha3/' + '*' + '"'
    $cmd += ' --exclude-files "lib-q-sig/' + '*' + '" --exclude-files "lib-q-aead/' + '*' + '" --exclude-files "lib-q-platform/' + '*' + '"'
    $cmd += ' --exclude-files "lib-q-utils/' + '*' + '" --exclude-files "lib-q-zkp/' + '*' + '"'
    $cmd += ' --exclude-files "lib-q-core/src/wasm/' + '*' + '" --exclude-files "lib-q-core\src\wasm\' + '*' + '"'
    $cmd += ' --include-files "lib-q-core/src/' + '*' + '" --include-files "lib-q-core/src/' + '*' + '*' + '" --include-files "lib-q-core\src\' + '*' + '"'
}
if ($Crate -eq "lib-q") {
    $cmd += ' --include-files "lib-q/src/' + '*' + '" --include-files "lib-q/src/' + '*' + '*' + '" --include-files "lib-q\src\' + '*' + '"'
}
if ($Crate -eq "lib-q-keccak") {
    $cmd += ' --include-files "lib-q-keccak/src/' + '*' + '" --include-files "lib-q-keccak/src/' + '*' + '*' + '" --include-files "lib-q-keccak\src\' + '*' + '"'
    $cmd += ' --exclude-files "lib-q-keccak/src/advanced_simd.rs" --exclude-files "lib-q-keccak\src\advanced_simd.rs"'
}
if ($Crate -eq "lib-q-hash") {
    $cmd += ' --include-files "lib-q-hash/src/' + '*' + '" --include-files "lib-q-hash/src/' + '*' + '*' + '" --include-files "lib-q-hash\src\' + '*' + '"'
}
if ($Crate -ne "" -and $Crate -ne "lib-q-core" -and $Crate -ne "lib-q" -and $Crate -ne "lib-q-keccak" -and $Crate -ne "lib-q-hash") {
    $cmd += Get-TarpaulinIncludeFlags -CrateName $Crate
}
if ($Crate -ne "" -and $cmd -notmatch '--include-files') {
    Write-Host "ERROR: tarpaulin command is missing --include-files for package $Crate" -ForegroundColor Red
    exit 1
}
$outputFormatParts = $OutputFormat -split ','
foreach ($rawOut in $outputFormatParts) {
    $f = $rawOut.Trim()
    if ($f.Length -gt 0) {
        $cmd += " --out $f"
    }
}
$cmd += " --output-dir $OutputDir"
if ($Crate -eq "lib-q-kem") {
    $cmd += " -- --test-threads=1"
}

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
