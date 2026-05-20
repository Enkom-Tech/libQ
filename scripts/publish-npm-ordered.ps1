# Publish @lib-q/* packages to npm in CD order (.github/workflows/cd.yml).
# Requires: npm login (or NODE_AUTH_TOKEN), wasm-pack, Node 20+, bash.
# Resume: -StartAt N (0-based). Dry-run: -DryRun. Skip wasm rebuild: -SkipBuild.
param(
    [int]$StartAt = 0,
    [switch]$DryRun,
    [switch]$SkipBuild,
    [string]$Version = "",
    [string]$Otp = ""
)

Set-Location (Join-Path $PSScriptRoot "..")

$bash = Get-Command bash -ErrorAction SilentlyContinue
if (-not $bash) {
    Write-Error "bash is required (Git Bash or WSL). Install Git for Windows or run scripts/publish-npm-ordered.sh on Linux/macOS."
    exit 127
}

$env:START_AT = "$StartAt"
if (-not $env:PYTHON) {
    foreach ($candidate in @(
            "C:\Program Files\Python312\python.exe",
            "C:\Program Files\Python3101\python.exe"
        )) {
        if (Test-Path $candidate) {
            $env:PYTHON = $candidate
            break
        }
    }
    if (-not $env:PYTHON) {
        $py = Get-Command py -ErrorAction SilentlyContinue
        if ($py) { $env:PYTHON = "py -3" }
    }
}
if ($DryRun) { $env:DRY_RUN = "1" } else { Remove-Item Env:DRY_RUN -ErrorAction SilentlyContinue }
if ($SkipBuild) { $env:SKIP_BUILD = "1" } else { Remove-Item Env:SKIP_BUILD -ErrorAction SilentlyContinue }
if ($Version) { $env:VERSION = $Version }
if (-not $Otp) {
    $Otp = Read-Host "Enter npm 2FA OTP (6 digits from your authenticator)"
}
if ($Otp) { $env:NPM_OTP = $Otp.Trim() }

$script = Join-Path $PSScriptRoot "publish-npm-ordered.sh"
& $bash.Source $script
exit $LASTEXITCODE
