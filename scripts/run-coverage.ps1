#!/usr/bin/env pwsh
# PowerShell script for running targeted test coverage analysis

param (
    [string]$Crate = "",
    [switch]$NoReference,
    [switch]$ShowReport,
    [string]$OutputDir = "coverage",
    [string]$OutputFormat = "Html",
    [switch]$IgnoreTests,
    [switch]$IgnorePanics,
    [string]$LineThreshold = "95",
    [string]$Toolchain = "stable"
)

# Set defaults for switch parameters
$NoReference = if ($PSBoundParameters.ContainsKey('NoReference')) { $NoReference } else { $true }
$ShowReport = if ($PSBoundParameters.ContainsKey('ShowReport')) { $ShowReport } else { $true }
$IgnoreTests = if ($PSBoundParameters.ContainsKey('IgnoreTests')) { $IgnoreTests } else { $true }
$IgnorePanics = if ($PSBoundParameters.ContainsKey('IgnorePanics')) { $IgnorePanics } else { $true }

# Create directory for coverage reports if it doesn't exist
if (-not (Test-Path -Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
    Write-Host "Created directory: $OutputDir"
}

# Build the tarpaulin command
$cmd = if ($Toolchain -eq "stable") {
    "cargo tarpaulin"
} else {
    "cargo +$Toolchain tarpaulin"
}

# Add package filter if specified
if ($Crate -ne "") {
    $cmd += " --packages $Crate"
}

# Add common flags
if ($IgnoreTests) {
    $cmd += " --ignore-tests"
}

if ($IgnorePanics) {
    $cmd += " --ignore-panics"
}

# Exclude reference implementations if requested
if ($NoReference) {
    $cmd += " --exclude-files 'reference/*'"
}

# Add output format
$cmd += " --out $OutputFormat --output-dir $OutputDir"

# Add line coverage threshold (removed as not supported by current tarpaulin version)
# We'll check the threshold manually after running

# Show the command
Write-Host "Running: $cmd"

# Execute the command
Invoke-Expression $cmd

# Show the report if requested
if ($ShowReport -and (Test-Path -Path "$OutputDir/index.html")) {
    Write-Host "Opening coverage report..."
    Start-Process "$OutputDir/index.html"
}

# Check if we met the threshold
$coverageFile = "$OutputDir/tarpaulin-report.html"
if (Test-Path -Path $coverageFile) {
    $content = Get-Content -Path $coverageFile -Raw
    if ($content -match "(\d+\.\d+)%") {
        $coverage = [double]$Matches[1]
        if ($coverage -lt [double]$LineThreshold) {
            Write-Host "❌ Coverage is $coverage%, which is below the $LineThreshold% threshold." -ForegroundColor Red
            exit 1
        } else {
            Write-Host "✅ Coverage is $coverage%, which meets or exceeds the $LineThreshold% threshold." -ForegroundColor Green
        }
    }
}
