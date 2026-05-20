# Publish workspace crates to crates.io in CD dependency order (.github/workflows/cd.yml).
# Requires: cargo login (API token). Stops on first hard failure.
# Resume: -StartAt N (0-based index into $packages below).
param([int]$StartAt = 0)

Set-Location (Join-Path $PSScriptRoot "..")

$packages = @(
    "lib-q-types",
    "lib-q-core", "lib-q-keccak",
    "lib-q-sha3",
    "lib-q-keccak-digest", "lib-q-utils", "lib-q-platform", "lib-q-saturnin",
    "lib-q-random", "lib-q-hqc-traits", "lib-q-duplex-aead", "lib-q-tweak-aead",
    "lib-q-romulus", "lib-q-ring", "lib-q-prf",
    "lib-q-k12", "lib-q-ml-kem", "lib-q-cb-kem",
    "lib-q-fn-dsa-comm", "lib-q-fn-dsa-kgen", "lib-q-fn-dsa-sign", "lib-q-fn-dsa-vrfy", "lib-q-fn-dsa-alg",
    "lib-q-fn-dsa", "lib-q-intrinsics",
    "lib-q-hqc", "lib-q-slh-dsa", "lib-q-lattice-zkp",
    "lib-q-ml-dsa", "lib-q-hash", "lib-q-aead", "lib-q-kem", "lib-q-sig", "lib-q-ring-sig",
    "lib-q-hpke", "lib-q-sca-test",
    "lib-q-stark-util", "lib-q-stark-rayon",
    "lib-q-stark-field", "lib-q-stark-symmetric",
    "lib-q-stark-matrix", "lib-q-stark-dft", "lib-q-stark-commit",
    "lib-q-stark-mds", "lib-q-stark-field-testing", "lib-q-stark-shake256",
    "lib-q-stark-shake128", "lib-q-stark-sha3-256",
    "lib-q-stark-mersenne31", "lib-q-stark-monty31",
    "lib-q-stark-challenger", "lib-q-stark-interpolation",
    "lib-q-poseidon", "lib-q-stark-merkle", "lib-q-stark-fri", "lib-q-stark-air",
    "lib-q-stark",
    "lib-q-plonky-multilinear-util", "lib-q-plonky-keccak-air",
    "lib-q-plonky-lookup", "lib-q-plonky-uni-stark",
    "lib-q-plonky-batch-stark", "lib-q-plonky",
    "lib-q-zkp",
    "lib-q"
)

$nestedManifest = @{
    "lib-q-fn-dsa-comm" = "lib-q-fn-dsa/fn-dsa-comm/Cargo.toml"
    "lib-q-fn-dsa-kgen" = "lib-q-fn-dsa/fn-dsa-kgen/Cargo.toml"
    "lib-q-fn-dsa-sign" = "lib-q-fn-dsa/fn-dsa-sign/Cargo.toml"
    "lib-q-fn-dsa-vrfy" = "lib-q-fn-dsa/fn-dsa-vrfy/Cargo.toml"
    "lib-q-fn-dsa-alg"  = "lib-q-fn-dsa/fn-dsa/Cargo.toml"
}

$log = Join-Path $PSScriptRoot "publish-crates-io-ordered.log"
Add-Content $log "`n=== run StartAt=$StartAt $(Get-Date -Format o) ==="

# `cargo publish` resolves dev-dependencies from crates.io; strip until those crates exist.
$m31Idx = [array]::IndexOf($packages, "lib-q-stark-mersenne31")
$montyIdx = [array]::IndexOf($packages, "lib-q-stark-monty31")
$uniStarkIdx = [array]::IndexOf($packages, "lib-q-plonky-uni-stark")
$lookupIdx = [array]::IndexOf($packages, "lib-q-plonky-lookup")
$stripPublishManifests = @{
    "lib-q-stark-symmetric"         = "lib-q-stark-symmetric/Cargo.toml"
    "lib-q-stark-matrix"            = "lib-q-stark-matrix/Cargo.toml"
    "lib-q-stark-dft"               = "lib-q-stark-dft/Cargo.toml"
    "lib-q-stark-mds"               = "lib-q-stark-mds/Cargo.toml"
    "lib-q-plonky-multilinear-util" = "lib-q-plonky-multilinear-util/Cargo.toml"
    "lib-q-plonky-keccak-air"       = "lib-q-plonky-keccak-air/Cargo.toml"
    "lib-q-plonky-lookup"           = "lib-q-plonky-lookup/Cargo.toml"
}
$script:ManifestBackups = @{}

function Restore-StrippedManifests {
    foreach ($path in @($script:ManifestBackups.Keys)) {
        Set-Content -Path $path -Value $script:ManifestBackups[$path] -NoNewline
        $script:ManifestBackups.Remove($path) | Out-Null
    }
}

function Invoke-StripForwardPublishDeps([string]$pkg, [int]$index) {
    Restore-StrippedManifests
    if (-not $stripPublishManifests.ContainsKey($pkg)) { return }
    $path = Join-Path (Get-Location) $stripPublishManifests[$pkg]
    $script:ManifestBackups[$path] = Get-Content -Path $path -Raw
    $lines = Get-Content -Path $path
    $filtered = foreach ($line in $lines) {
        if ($index -lt $m31Idx -and $line -match '^\s*lib-q-stark-mersenne31\s*=') { continue }
        if ($index -lt $montyIdx -and $line -match '^\s*lib-q-stark-monty31\s*=') { continue }
        if ($index -lt $uniStarkIdx -and $line -match '^\s*lib-q-plonky-uni-stark\s*=') { continue }
        if ($index -lt $lookupIdx -and $line -match '^\s*lib-q-plonky-lookup\s*=') { continue }
        $line
    }
    Set-Content -Path $path -Value $filtered
}

for ($i = $StartAt; $i -lt $packages.Count; $i++) {
    $pkg = $packages[$i]
    $msg = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Publishing $pkg ..."
    Write-Host $msg
    Add-Content $log $msg

    $publishArgs = @("publish", "--allow-dirty")
    if ($nestedManifest.ContainsKey($pkg)) {
        $publishArgs += @("--manifest-path", $nestedManifest[$pkg])
    } else {
        $publishArgs += @("-p", $pkg)
    }

    $published = $false
    $maxAttempts = 12
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        Invoke-StripForwardPublishDeps $pkg $i
        $out = @()
        $code = 1
        try {
            # Do not pipe cargo: PowerShell sets $LASTEXITCODE to the pipeline tail, not cargo.
            $raw = & cargo @publishArgs 2>&1
            $code = $LASTEXITCODE
            if ($null -eq $code) { $code = 1 }
            $out = @($raw | ForEach-Object { "$_" })
            $out | Add-Content $log
            $out | Write-Host
        } finally {
            Restore-StrippedManifests
        }

        if ($code -eq 0) {
            $published = $true
            break
        }

        $joined = $out -join "`n"
        if ($joined -match "already exists on crates.io" -or $joined -match "is already uploaded") {
            $skip = "SKIP (already published): $pkg"
            Write-Host $skip -ForegroundColor Cyan
            Add-Content $log $skip
            $published = $true
            break
        }

        $isRateLimited = $joined -match "429|too many new crates|Too Many Requests"
        if ($isRateLimited) {
            $wait = 660
            # crates.io: "... try again after Wed, 20 May 2026 14:16:02 GMT and see https://..."
            if ($joined -match "try again after (.+? GMT)\b") {
                $retryAfter = $Matches[1].Trim()
                try {
                    $until = [DateTime]::ParseExact(
                        $retryAfter,
                        "ddd, dd MMM yyyy HH:mm:ss 'GMT'",
                        [System.Globalization.CultureInfo]::InvariantCulture,
                        [System.Globalization.DateTimeStyles]::AssumeUniversal
                    ).ToUniversalTime()
                    $secs = [int]($until - [DateTime]::UtcNow).TotalSeconds + 30
                    if ($secs -gt 60) { $wait = $secs }
                    $retryMsg = "crates.io retry after $retryAfter UTC -> waiting ${wait}s (until ~$($until.ToString('o')))"
                    Write-Host $retryMsg -ForegroundColor DarkYellow
                    Add-Content $log $retryMsg
                } catch {
                    $wparse = "Could not parse retry time '$retryAfter'; using ${wait}s fallback"
                    Write-Host $wparse -ForegroundColor DarkYellow
                    Add-Content $log $wparse
                }
            }
            if ($attempt -ge $maxAttempts) {
                break
            }
            $wmsg = "Rate limited on $pkg; waiting ${wait}s (attempt $attempt/$maxAttempts)..."
            Write-Host $wmsg -ForegroundColor Yellow
            Add-Content $log $wmsg
            Start-Sleep -Seconds $wait
            continue
        }

        $err = "FAILED: $pkg (exit $code)"
        Write-Host $err -ForegroundColor Red
        Add-Content $log $err
        exit $code
    }
    if (-not $published) {
        $err = "FAILED: $pkg (rate limit retries exhausted)"
        Write-Host $err -ForegroundColor Red
        Add-Content $log $err
        exit 101
    }
    $ok = "OK: $pkg"
    Write-Host $ok -ForegroundColor Green
    Add-Content $log $ok
    Start-Sleep -Seconds 90
}

Write-Host "All $($packages.Count) workspace crates published." -ForegroundColor Green
