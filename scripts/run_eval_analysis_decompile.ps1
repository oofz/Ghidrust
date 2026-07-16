# Runs the analyzer + decompile evaluation and prints the report locations.
#
# Usage:
#   pwsh scripts/run_eval_analysis_decompile.ps1            # debug profile (fast)
#   pwsh scripts/run_eval_analysis_decompile.ps1 -Release   # release timings

param(
    [switch]$Release
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$profileArgs = @()
if ($Release) { $profileArgs += "--release" }

$args = @(
    "test",
    "-p", "ghidrust-cli",
    "--test", "eval_analysis_decompile"
) + $profileArgs + @("--", "--nocapture")

Write-Host "[eval] cargo $($args -join ' ')" -ForegroundColor Cyan
& cargo @args
$exit = $LASTEXITCODE

$md = Join-Path $root "dev\EVAL_ANALYSIS_DECOMPILE_REPORT.md"
$json = Join-Path $root "dev\eval_analysis_decompile.json"

Write-Host ""
if (Test-Path $md)   { Write-Host "[eval] report: $md" -ForegroundColor Green }
if (Test-Path $json) { Write-Host "[eval] json  : $json" -ForegroundColor Green }

exit $exit
