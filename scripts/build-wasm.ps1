# lib-Q WASM Build Script (PowerShell Version)
# This script builds WASM binaries from the lib-Q post-quantum cryptography library

param(
    [switch]$Force,
    [switch]$Help,
    [switch]$Verbose
)

if ($Help) {
    Write-Host "lib-Q WASM Build Script"
    Write-Host ""
    Write-Host "Usage: .\scripts\build-wasm.ps1 [-Force] [-Help] [-Verbose]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Force    Skip confirmation prompts"
    Write-Host "  -Help     Show this help message"
    Write-Host "  -Verbose  Show detailed output"
    Write-Host ""
    Write-Host "This script builds WASM binaries from the lib-Q post-quantum cryptography library."
    Write-Host "It requires wasm-pack to be installed and configured."
    exit 0
}

$ErrorActionPreference = "Stop"

Write-Host "Building lib-Q WASM Binaries..." -ForegroundColor Green

# Configuration
$WASM_OUTPUT_DIR = "pkg"

# Function to print colored output
function Write-Status {
    param(
        [string]$Status,
        [string]$Message
    )
    
    switch ($Status) {
        "PASS" { Write-Host "PASS: $Message" -ForegroundColor Green }
        "FAIL" { Write-Host "FAIL: $Message" -ForegroundColor Red }
        "WARN" { Write-Host "WARN: $Message" -ForegroundColor Yellow }
        "INFO" { Write-Host "INFO: $Message" -ForegroundColor Blue }
    }
}

# Function to check if wasm-pack is available
function Test-WasmPack {
    try {
        $wasmPackVersion = & wasm-pack --version 2>&1 | Select-Object -First 1
        Write-Status "PASS" "wasm-pack found: $wasmPackVersion"
        return $true
    } catch {
        Write-Status "FAIL" "wasm-pack not found. Please install wasm-pack:"
        Write-Host "   cargo install wasm-pack" -ForegroundColor Yellow
        return $false
    }
}

# Function to check if Rust is available
function Test-Rust {
    try {
        $rustVersion = & rustc --version 2>&1 | Select-Object -First 1
        Write-Status "PASS" "Rust found: $rustVersion"
        return $true
    } catch {
        Write-Status "FAIL" "Rust not found. Please install Rust from https://rustup.rs/"
        return $false
    }
}

# Function to check WASM target
function Test-WasmTarget {
    try {
        $targets = & rustup target list --installed 2>&1
        if ($targets -contains "wasm32-unknown-unknown") {
            Write-Status "PASS" "WASM target installed"
            return $true
        } else {
            Write-Status "WARN" "WASM target not installed. Installing..."
            & rustup target add wasm32-unknown-unknown
            if ($LASTEXITCODE -eq 0) {
                Write-Status "PASS" "WASM target installed successfully"
                return $true
            } else {
                Write-Status "FAIL" "Failed to install WASM target"
                return $false
            }
        }
    } catch {
        Write-Status "FAIL" "Failed to check WASM target"
        return $false
    }
}

# Function to clean previous builds
function Remove-PreviousBuild {
    Write-Status "INFO" "Cleaning previous build artifacts..."
    
    if (Test-Path $WASM_OUTPUT_DIR) {
        Remove-Item -Recurse -Force $WASM_OUTPUT_DIR
        Write-Status "PASS" "Cleaned previous build artifacts"
    }
}

# Function to build WASM
function Invoke-WasmBuild {
    Write-Status "INFO" "Building WASM module..."
    
    # Build command for lib-Q
    $buildCommand = @(
        "wasm-pack", "build",
        "--target", "web",
        "--out-dir", $WASM_OUTPUT_DIR,
        "--release",
        "--",
        "--features", "wasm"
    )
    
    if ($Verbose) {
        Write-Host "Running: $($buildCommand -join ' ')" -ForegroundColor Gray
    }
    
    try {
        & $buildCommand[0] $buildCommand[1..($buildCommand.Length-1)]
        
        if ($LASTEXITCODE -eq 0) {
            Write-Status "PASS" "WASM build completed successfully"
            return $true
        } else {
            Write-Status "FAIL" "WASM build failed"
            return $false
        }
    } catch {
        Write-Status "FAIL" "WASM build failed: $($_.Exception.Message)"
        return $false
    }
}

# Function to generate checksums
function New-Checksums {
    Write-Status "INFO" "Generating checksums..."
    
    if (!(Test-Path $WASM_OUTPUT_DIR)) {
        Write-Status "FAIL" "WASM output directory not found"
        return $false
    }
    
    Push-Location $WASM_OUTPUT_DIR
    
    try {
        $wasmFiles = Get-ChildItem -Filter "*.wasm" -ErrorAction SilentlyContinue
        
        foreach ($wasmFile in $wasmFiles) {
            Write-Status "INFO" "Generating checksum for $($wasmFile.Name)..."
            
            # Generate SHA-256 checksum
            $hash = Get-FileHash -Path $wasmFile.FullName -Algorithm SHA256
            $checksumHex = $hash.Hash.ToLower()
            
            # Save checksum file
            "$checksumHex  $($wasmFile.Name)" | Out-File -FilePath "$($wasmFile.Name).sha256" -Encoding ascii
            
            # Convert to base64 for configuration (simplified approach)
            $base64Checksum = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($checksumHex))
            
            "sha256-$base64Checksum" | Out-File -FilePath "$($wasmFile.Name).config.checksum" -Encoding ascii
            
            Write-Status "PASS" "$($wasmFile.Name) checksum: sha256-$base64Checksum"
        }
        
        if ($wasmFiles.Count -eq 0) {
            Write-Status "WARN" "No WASM files found in $WASM_OUTPUT_DIR"
            return $false
        }
        
        return $true
    } finally {
        Pop-Location
    }
}

# Function to verify checksums
function Test-Checksums {
    Write-Status "INFO" "Verifying checksums..."
    
    if (!(Test-Path $WASM_OUTPUT_DIR)) {
        Write-Status "FAIL" "WASM output directory not found"
        return $false
    }
    
    Push-Location $WASM_OUTPUT_DIR
    
    try {
        $checksumFiles = Get-ChildItem -Filter "*.wasm.sha256" -ErrorAction SilentlyContinue
        
        foreach ($checksumFile in $checksumFiles) {
            Write-Status "INFO" "Verifying $($checksumFile.Name)..."
            
            $content = Get-Content $checksumFile.FullName
            $expectedHash = $content.Split(' ')[0]
            $fileName = $content.Split(' ')[1]
            
            if (Test-Path $fileName) {
                $actualHash = (Get-FileHash -Path $fileName -Algorithm SHA256).Hash.ToLower()
                
                if ($actualHash -eq $expectedHash) {
                    Write-Status "PASS" "$($checksumFile.Name) verified"
                } else {
                    Write-Status "FAIL" "$($checksumFile.Name) verification failed"
                    return $false
                }
            } else {
                Write-Status "FAIL" "File not found: $fileName"
                return $false
            }
        }
        
        if ($checksumFiles.Count -eq 0) {
            Write-Status "WARN" "No checksum files found"
            return $false
        }
        
        return $true
    } finally {
        Pop-Location
    }
}

# Function to show build summary
function Show-BuildSummary {
    Write-Host ""
    Write-Host "Build Summary:" -ForegroundColor Cyan
    
    if (Test-Path $WASM_OUTPUT_DIR) {
        $wasmFiles = Get-ChildItem -Path $WASM_OUTPUT_DIR -Filter "*.wasm" -ErrorAction SilentlyContinue
        $jsFiles = Get-ChildItem -Path $WASM_OUTPUT_DIR -Filter "*.js" -ErrorAction SilentlyContinue
        
        foreach ($wasmFile in $wasmFiles) {
            $size = [math]::Round($wasmFile.Length / 1KB, 2)
            Write-Host "  WASM Binary: $($wasmFile.Name) ($size KB)" -ForegroundColor Green
        }
        
        foreach ($jsFile in $jsFiles) {
            $size = [math]::Round($jsFile.Length / 1KB, 2)
            Write-Host "  JS Bindings: $($jsFile.Name) ($size KB)" -ForegroundColor Green
        }
        
        Write-Host ""
        Write-Host "  Output directory: $WASM_OUTPUT_DIR" -ForegroundColor Gray
        Write-Host "  Checksum files: $WASM_OUTPUT_DIR\*.sha256" -ForegroundColor Gray
    } else {
        Write-Status "WARN" "No build artifacts found"
    }
}

# Function to show next steps
function Show-NextSteps {
    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Cyan
    Write-Host "  1. Test the WASM module: npm test" -ForegroundColor White
    Write-Host "  2. Run the application with WASM support" -ForegroundColor White
    Write-Host "  3. For production: npm run build" -ForegroundColor White
    Write-Host ""
    Write-Host "  WASM files are in: $WASM_OUTPUT_DIR" -ForegroundColor Gray
    Write-Host "  Include in HTML: script src='$WASM_OUTPUT_DIR\lib-q.js'" -ForegroundColor Gray
}

# Main execution
function Main {
    Write-Host "Starting lib-Q WASM build process..." -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan
    
    # Check prerequisites
    if (!(Test-Rust)) {
        exit 1
    }
    
    if (!(Test-WasmPack)) {
        exit 1
    }
    
    if (!(Test-WasmTarget)) {
        exit 1
    }
    
    Write-Host ""
    Write-Host "Building lib-Q post-quantum cryptography library for WASM..." -ForegroundColor White
    Write-Host "   Features: wasm-bindgen, js-sys, web-sys" -ForegroundColor Gray
    Write-Host "   Target: wasm32-unknown-unknown" -ForegroundColor Gray
    Write-Host "   Output: $WASM_OUTPUT_DIR" -ForegroundColor Gray
    Write-Host ""
    
    if (!$Force) {
        $response = Read-Host "Continue with WASM build? (y/N)"
        if ($response -notin @('y', 'Y', 'yes', 'Yes', 'YES')) {
            Write-Status "WARN" "Build cancelled"
            exit 0
        }
    }
    
    # Clean previous builds
    Remove-PreviousBuild
    
    # Build WASM
    if (!(Invoke-WasmBuild)) {
        exit 1
    }
    
    # Generate checksums
    if (!(New-Checksums)) {
        Write-Status "WARN" "Failed to generate checksums"
    }
    
    # Verify checksums
    if (!(Test-Checksums)) {
        Write-Status "WARN" "Failed to verify checksums"
    }
    
    # Show results
    Show-BuildSummary
    Show-NextSteps
    
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Status "PASS" "lib-Q WASM build process completed successfully!"
    Write-Host "==================================================" -ForegroundColor Cyan
}

# Run main function
try {
    Main
} catch {
    Write-Status "FAIL" "Build failed: $($_.Exception.Message)"
    if ($Verbose) {
        Write-Host $_.Exception.StackTrace -ForegroundColor Red
    }
    exit 1
}
