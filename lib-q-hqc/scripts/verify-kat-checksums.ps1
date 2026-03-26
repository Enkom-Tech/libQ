#!/usr/bin/env pwsh
# HQC KAT File Checksum Verification Script
# Compares our KAT files against the official NIST HQC submission

param(
    [switch]$Verbose = $false
)

$ErrorActionPreference = "Stop"

$OfficialSubmissionRoot = $env:HQC_OFFICIAL_SUBMISSION_ROOT
if ([string]::IsNullOrWhiteSpace($OfficialSubmissionRoot)) {
    Write-Host "Set HQC_OFFICIAL_SUBMISSION_ROOT to the root of the NIST HQC submission package (directory containing KATs/)." -ForegroundColor Red
    exit 2
}
$OfficialKatDir = Join-Path $OfficialSubmissionRoot "KATs/Reference_Implementation/hqc-128"

# Define file paths
$OurKats = @{
    "hqc-1" = @{
        "req" = "lib-q-hqc/kats/ref/hqc-1/PQCkemKAT_2321.req"
        "rsp" = "lib-q-hqc/kats/ref/hqc-1/PQCkemKAT_2321.rsp"
        "intermediates" = "lib-q-hqc/kats/ref/hqc-1/intermediates_values"
    }
}

$OfficialKats = @{
    "hqc-128" = @{
        "req" = Join-Path $OfficialKatDir "hqc-128_kat.req"
        "rsp" = Join-Path $OfficialKatDir "hqc-128_kat.rsp"
        "intermediates" = Join-Path $OfficialKatDir "hqc-128_intermediates_values"
    }
}

function Get-FileChecksum {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        return $null
    }
    
    $content = Get-Content $FilePath -Raw -Encoding UTF8
    $hash = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($content)
    $hashBytes = $hash.ComputeHash($bytes)
    $hash.Dispose()
    
    return [System.BitConverter]::ToString($hashBytes) -replace '-', ''
}

function Compare-Files {
    param(
        [string]$OurFile,
        [string]$OfficialFile,
        [string]$Description
    )
    
    Write-Host "`n=== $Description ===" -ForegroundColor Cyan
    
    $ourExists = Test-Path $OurFile
    $officialExists = Test-Path $OfficialFile
    
    if (-not $ourExists) {
        Write-Host "❌ Our file missing: $OurFile" -ForegroundColor Red
        return $false
    }
    
    if (-not $officialExists) {
        Write-Host "❌ Official file missing: $OfficialFile" -ForegroundColor Red
        return $false
    }
    
    $ourChecksum = Get-FileChecksum $OurFile
    $officialChecksum = Get-FileChecksum $OfficialFile
    
    Write-Host "Our file: $OurFile" -ForegroundColor Yellow
    Write-Host "Our checksum: $ourChecksum" -ForegroundColor Yellow
    Write-Host "Official file: $OfficialFile" -ForegroundColor Yellow
    Write-Host "Official checksum: $officialChecksum" -ForegroundColor Yellow
    
    if ($ourChecksum -eq $officialChecksum) {
        Write-Host "✅ Files match exactly" -ForegroundColor Green
        return $true
    } else {
        Write-Host "❌ Files differ" -ForegroundColor Red
        
        if ($Verbose) {
            # Show file sizes
            $ourSize = (Get-Item $OurFile).Length
            $officialSize = (Get-Item $OfficialFile).Length
            Write-Host "Our file size: $ourSize bytes" -ForegroundColor Yellow
            Write-Host "Official file size: $officialSize bytes" -ForegroundColor Yellow
            
            # Show first few lines for comparison
            Write-Host "`nFirst 5 lines of our file:" -ForegroundColor Yellow
            Get-Content $OurFile | Select-Object -First 5 | ForEach-Object { Write-Host "  $_" }
            
            Write-Host "`nFirst 5 lines of official file:" -ForegroundColor Yellow
            Get-Content $OfficialFile | Select-Object -First 5 | ForEach-Object { Write-Host "  $_" }
        }
        
        return $false
    }
}

# Main verification
Write-Host "HQC KAT File Checksum Verification" -ForegroundColor Green
Write-Host "===================================" -ForegroundColor Green

$allMatch = $true

# Compare HQC-1 (our) vs HQC-128 (official)
$comparisons = @(
    @{
        "Our" = $OurKats["hqc-1"]["req"]
        "Official" = $OfficialKats["hqc-128"]["req"]
        "Description" = "HQC-1 Request Files (PQCkemKAT_2321.req vs hqc-128_kat.req)"
    },
    @{
        "Our" = $OurKats["hqc-1"]["rsp"]
        "Official" = $OfficialKats["hqc-128"]["rsp"]
        "Description" = "HQC-1 Response Files (PQCkemKAT_2321.rsp vs hqc-128_kat.rsp)"
    },
    @{
        "Our" = $OurKats["hqc-1"]["intermediates"]
        "Official" = $OfficialKats["hqc-128"]["intermediates"]
        "Description" = "HQC-1 Intermediate Values (intermediates_values vs hqc-128_intermediates_values)"
    }
)

foreach ($comparison in $comparisons) {
    $match = Compare-Files -OurFile $comparison.Our -OfficialFile $comparison.Official -Description $comparison.Description
    if (-not $match) {
        $allMatch = $false
    }
}

# Summary
Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
if ($allMatch) {
    Write-Host "✅ All KAT files match the official NIST HQC submission exactly" -ForegroundColor Green
    Write-Host "✅ KAT provenance verified - files are authentic" -ForegroundColor Green
} else {
    Write-Host "❌ Some KAT files differ from the official submission" -ForegroundColor Red
    Write-Host "⚠️  Manual review required to determine if differences are acceptable" -ForegroundColor Yellow
}

# Generate provenance report
$provenanceReport = @"
# HQC KAT File Provenance Report

Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC")

## Source Verification

### Official NIST HQC Submission
- **Source**: NIST Round 2 HQC submission package
- **Root**: set via environment variable `HQC_OFFICIAL_SUBMISSION_ROOT` when running verification
- **Version**: Round 2 submission (as submitted to NIST)
- **Algorithm**: HQC (Hamming Quasi-Cyclic)

### Our KAT Files
- **Location**: `lib-q-hqc/kats/ref/`
- **Generated**: From official submission package
- **Verification Status**: $(if ($allMatch) { "✅ VERIFIED - All files match official submission exactly" } else { "❌ DIFFERENCES DETECTED - Manual review required" })

## File Mappings

| Our File | Official File | Status |
|----------|---------------|--------|
| `lib-q-hqc/kats/ref/hqc-1/PQCkemKAT_2321.req` | `KATs/Reference_Implementation/hqc-128/hqc-128_kat.req` (under submission root) | $(if ((Compare-Files -OurFile $OurKats["hqc-1"]["req"] -OfficialFile $OfficialKats["hqc-128"]["req"] -Description "Check")) { "✅ Match" } else { "❌ Differ" }) |
| `lib-q-hqc/kats/ref/hqc-1/PQCkemKAT_2321.rsp` | `KATs/Reference_Implementation/hqc-128/hqc-128_kat.rsp` (under submission root) | $(if ((Compare-Files -OurFile $OurKats["hqc-1"]["rsp"] -OfficialFile $OfficialKats["hqc-128"]["rsp"] -Description "Check")) { "✅ Match" } else { "❌ Differ" }) |
| `lib-q-hqc/kats/ref/hqc-1/intermediates_values` | `KATs/Reference_Implementation/hqc-128/hqc-128_intermediates_values` (under submission root) | $(if ((Compare-Files -OurFile $OurKats["hqc-1"]["intermediates"] -OfficialFile $OfficialKats["hqc-128"]["intermediates"] -Description "Check")) { "✅ Match" } else { "❌ Differ" }) |

## Compliance Status

$(if ($allMatch) {
"✅ **FULL COMPLIANCE**: All KAT files are byte-exact matches with the official NIST HQC submission.

This confirms:
- Authentic test vectors from authoritative source
- No modifications or corruption during transfer
- Ready for formal compliance testing"
} else {
"⚠️ **REVIEW REQUIRED**: Some KAT files differ from the official submission.

Next steps:
1. Investigate source of differences
2. Determine if differences are acceptable (e.g., formatting, comments)
3. Document any intentional modifications
4. Re-verify after corrections"
})

## References

- [NIST PQC Standardization Process](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [HQC Official Submission](https://pqc-hqc.org/)
- [HQC specification and downloads](https://pqc-hqc.org/)
"@

# Create docs directory if it doesn't exist
$docsDir = "lib-q-hqc/docs"
if (-not (Test-Path $docsDir)) {
    New-Item -ItemType Directory -Path $docsDir -Force | Out-Null
}

# Write provenance report
$provenanceReport | Out-File -FilePath "$docsDir/kat-provenance.md" -Encoding UTF8
Write-Host "`n📄 Provenance report written to: $docsDir/kat-provenance.md" -ForegroundColor Green

exit $(if ($allMatch) { 0 } else { 1 })
