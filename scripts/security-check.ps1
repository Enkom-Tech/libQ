# lib-Q security check (Windows entry point).
#
# This used to be a 185-line PowerShell reimplementation of security-check.sh, and it
# carried the same defect: every check scanned a repo-root `src\` directory that stopped
# existing when libQ split into `lib-q-*` crates, so no check could reach its FAIL branch.
# The PowerShell version was marginally less silent about it -- `Get-ChildItem -Path "src"`
# printed "Cannot find path", where the shell version routed the same error to /dev/null --
# but it still exited 0 and printed a hardcoded summary of check marks either way.
#
# Rather than fix the same logic twice and let the two drift, this is now a thin wrapper
# over the one implementation. The real work lives in:
#   scripts/security-check.sh                        orchestration + summary
#   scripts/security_check_classical_crypto.py       the check itself, with a self-test
#   scripts/classical-crypto-allowlist.txt           the reviewed surface
#
# bash is available on Windows dev machines here via Git for Windows, which the repo
# already requires: the ci-guard-*.sh gates in .github/workflows are run the same way.

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$shellCheck = Join-Path $scriptDir 'security-check.sh'

if (-not (Test-Path $shellCheck)) {
    Write-Host "FAIL: $shellCheck is missing" -ForegroundColor Red
    exit 1
}

# Find Git for Windows' bash SPECIFICALLY -- do not just take the first `bash` on PATH.
#
# On a default Windows 10/11 install, `Get-Command bash` resolves to C:\Windows\system32\
# bash.exe, the WSL launcher. That is a Linux bash: it cannot open `C:/Users/...` (it wants
# /mnt/c/Users/...), so handing it this script fails with a confusing
# "/bin/bash: C:/.../security-check.sh: No such file or directory" and exit 127 even though
# the file plainly exists. OBSERVED on this machine, where PATH offers system32\bash.exe and
# the WindowsApps alias and neither is Git bash.
#
# Git bash sits next to git.exe, one directory up from cmd\ or mingw64\bin\, so derive it
# from wherever git itself was found rather than guessing an install path.
$bashPath = $null
$candidates = @()

$gitCmd = Get-Command git -ErrorAction SilentlyContinue
if ($gitCmd) {
    $gitRoot = Split-Path (Split-Path $gitCmd.Source)   # ...\Git\cmd\git.exe -> ...\Git
    $candidates += (Join-Path $gitRoot 'bin\bash.exe')
    $candidates += (Join-Path (Split-Path $gitRoot) 'bin\bash.exe')  # ...\Git\mingw64\bin\git.exe
}
$candidates += (Join-Path $env:ProgramFiles 'Git\bin\bash.exe')
if (${env:ProgramFiles(x86)}) {
    $candidates += (Join-Path ${env:ProgramFiles(x86)} 'Git\bin\bash.exe')
}

foreach ($candidate in $candidates) {
    if ($candidate -and (Test-Path $candidate)) { $bashPath = $candidate; break }
}

# Last resort: any bash on PATH that is not the WSL launcher.
if (-not $bashPath) {
    foreach ($onPath in (Get-Command bash -All -ErrorAction SilentlyContinue)) {
        if ($onPath.Source -notmatch '\\(system32|WindowsApps)\\') { $bashPath = $onPath.Source; break }
    }
}

if (-not $bashPath) {
    Write-Host "FAIL: Git for Windows' bash was not found." -ForegroundColor Red
    Write-Host "      (A WSL bash on PATH cannot run this script with a Windows path.)" -ForegroundColor Yellow
    Write-Host "      Install Git for Windows, or run the check directly:" -ForegroundColor Yellow
    Write-Host "      python scripts/security_check_classical_crypto.py ." -ForegroundColor Yellow
    exit 1
}

# Hand bash a forward-slash path. A Windows path reaches it as a single argument in which
# each backslash is an escape character, so `C:\...\scripts\security-check.sh` arrives as
# `C:UsersXtreme-W...scriptssecurity-check.sh` and the run dies with exit 127. Git for
# Windows' bash accepts the `C:/...` form directly.
$shellCheckPosix = $shellCheck -replace '\\', '/'

& $bashPath $shellCheckPosix @args
exit $LASTEXITCODE
