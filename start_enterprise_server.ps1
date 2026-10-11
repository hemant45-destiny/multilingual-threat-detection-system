# PolyShield(TM) Enterprise Cyber Defense Platform
# PowerShell Production Launcher

Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "  [🛡️] POLYSHIELD™ ENTERPRISE CYBER DEFENSE PLATFORM" -ForegroundColor Green
Write-Host "       Autonomous Multilingual Threat Intelligence & SOC Triage Gateway" -ForegroundColor Yellow
Write-Host "       Commercial Enterprise Edition v2.4 (Production Ready)" -ForegroundColor Gray
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host " [✔] Launching Enterprise Gateway on http://localhost:8000 ..." -ForegroundColor Green
Write-Host " [✔] OpenAPI Technical Reference: http://localhost:8000/docs" -ForegroundColor Gray
Write-Host " Press Ctrl+C to terminate gateway." -ForegroundColor DarkGray
Write-Host ""

if (Get-Command py -ErrorAction SilentlyContinue) {
    py run.py
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    python run.py
} else {
    Write-Host "[ERROR] Python 3.10+ was not found on this system!" -ForegroundColor Red
}
