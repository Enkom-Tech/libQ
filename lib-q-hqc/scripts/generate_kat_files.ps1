# PowerShell script to generate KAT files from HQC reference implementation
# This script compiles and runs the KAT generator from the C reference

param(
    [switch]$Force
)

# Colors for output
$ErrorColor = "Red"
$SuccessColor = "Green"
$WarningColor = "Yellow"

Write-Host "Generating HQC KAT files from reference implementation..." -ForegroundColor $SuccessColor

# Base directory for reference implementation
$RefDir = "../../reference/hqc-avx2/Reference_Implementation 2"
$KatDir = "tests/kat_data"

# Create KAT data directory
if (!(Test-Path $KatDir)) {
    New-Item -ItemType Directory -Path $KatDir -Force | Out-Null
}

# Function to generate KAT files for a parameter set
function Generate-KatForParams {
    param($Params)
    
    $ParamDir = "$RefDir/$Params"
    
    Write-Host "Generating KAT files for $Params..." -ForegroundColor $WarningColor
    
    if (!(Test-Path $ParamDir)) {
        Write-Host "Error: Parameter directory $ParamDir not found" -ForegroundColor $ErrorColor
        return $false
    }
    
    Push-Location $ParamDir
    
    try {
        # Clean previous builds
        if (Test-Path "Makefile") {
            & make clean 2>$null
        }
        
        # Compile KAT generator
        Write-Host "Compiling KAT generator for $Params..."
        $MakeTarget = "${Params}-kat"
        $MakeResult = & make $MakeTarget 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Warning: Could not compile KAT generator for $Params" -ForegroundColor $ErrorColor
            Write-Host "This might be due to missing dependencies (NTL, gf2x, OpenSSL)"
            Write-Host "Skipping $Params..."
            return $true
        }
        
        # Run KAT generator
        Write-Host "Running KAT generator for $Params..."
        $KatBinary = "bin/${Params}-kat.exe"
        if (!(Test-Path $KatBinary)) {
            $KatBinary = "bin/${Params}-kat"
        }
        
        if (Test-Path $KatBinary) {
            & $KatBinary
            Write-Host "KAT files generated for $Params" -ForegroundColor $SuccessColor
        } else {
            Write-Host "Error: KAT generator binary not found for $Params" -ForegroundColor $ErrorColor
            return $false
        }
        
        # Copy KAT files to our test directory
        $ReqFiles = Get-ChildItem -Path "." -Filter "PQCkemKAT_*.req" -ErrorAction SilentlyContinue
        $RspFiles = Get-ChildItem -Path "." -Filter "PQCkemKAT_*.rsp" -ErrorAction SilentlyContinue
        
        if ($ReqFiles -and $RspFiles) {
            Copy-Item $ReqFiles.FullName "../../../lib-q-hqc/$KatDir/"
            Copy-Item $RspFiles.FullName "../../../lib-q-hqc/$KatDir/"
            Write-Host "KAT files copied for $Params" -ForegroundColor $SuccessColor
        } else {
            Write-Host "Warning: KAT files not found for $Params" -ForegroundColor $ErrorColor
        }
        
        return $true
    }
    finally {
        Pop-Location
    }
}

# Generate KAT files for all parameter sets
$ParamSets = @("hqc-128-1", "hqc-192-1", "hqc-192-2", "hqc-256-1", "hqc-256-2", "hqc-256-3")

foreach ($Params in $ParamSets) {
    Generate-KatForParams -Params $Params
}

Write-Host "KAT file generation complete!" -ForegroundColor $SuccessColor
Write-Host "KAT files are available in: $KatDir"

# List generated files
if (Test-Path $KatDir) {
    Write-Host "Generated KAT files:" -ForegroundColor $WarningColor
    Get-ChildItem $KatDir | Format-Table Name, Length, LastWriteTime
}
