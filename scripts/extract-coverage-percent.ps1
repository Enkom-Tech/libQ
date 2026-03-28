# Read aggregate line coverage (0-100) from cargo-tarpaulin output in OutputDir.
# Prefers cobertura.xml; falls back to HTML. Writes percentage to stdout; exit 0 if ok.
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDir
)

$pct = $null

$xmlPath = Join-Path $OutputDir "cobertura.xml"
if (Test-Path -LiteralPath $xmlPath) {
    $line = Get-Content -LiteralPath $xmlPath -Raw
    if ($line -match 'line-rate="([0-9.]+)"') {
        $rate = [double]$Matches[1]
        $pct = [math]::Round($rate * 100, 4)
    }
}

if ($null -eq $pct) {
    foreach ($name in @("tarpaulin-report.html", "index.html")) {
        $htmlPath = Join-Path $OutputDir $name
        if (-not (Test-Path -LiteralPath $htmlPath)) { continue }
        $content = Get-Content -LiteralPath $htmlPath -Raw
        if ($content -match '([0-9]+(?:\.[0-9]+)?)\s*%') {
            $pct = [double]$Matches[1]
            break
        }
    }
}

if ($null -ne $pct -and $pct -ge 0 -and $pct -le 100) {
    Write-Output ("{0:g}" -f $pct)
    exit 0
}

exit 1
