# Read aggregate line or branch coverage (0-100) from cargo-tarpaulin output in OutputDir.
# Prefers cobertura.xml; falls back to HTML for line only. Branch: exit 2 if branches-valid=0.
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDir,
    [ValidateSet("Line", "Branch")]
    [string]$Metric = "Line"
)

$pct = $null

$xmlPath = Join-Path $OutputDir "cobertura.xml"
if (Test-Path -LiteralPath $xmlPath) {
    $raw = Get-Content -LiteralPath $xmlPath -Raw
    if ($Metric -eq "Branch") {
        $bv = 0
        if ($raw -match 'branches-valid="([0-9]+)"') {
            $bv = [int]$Matches[1]
        }
        if ($bv -le 0) {
            exit 2
        }
        if ($raw -match 'branch-rate="([0-9.]+)"') {
            $rate = [double]$Matches[1]
            $pct = [math]::Round($rate * 100, 4)
        }
    }
    elseif ($raw -match 'line-rate="([0-9.]+)"') {
        $rate = [double]$Matches[1]
        $pct = [math]::Round($rate * 100, 4)
    }
}

if ($null -eq $pct -and $Metric -eq "Line") {
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

if ($Metric -eq "Branch") {
    exit 2
}

exit 1
