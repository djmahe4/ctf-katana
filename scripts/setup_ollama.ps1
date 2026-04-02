# setup_ollama.ps1
# Automating Ollama setup for Phase 3: Research Scout

Write-Host "[*] Checking for Ollama..." -ForegroundColor Cyan

$ollama = Get-Command ollama -ErrorAction SilentlyContinue

if ($null -eq $ollama) {
    Write-Host "[!] Ollama not found. Attempting installation via winget..." -ForegroundColor Yellow
    winget install Ollama.Ollama --accept-source-agreements --accept-package-agreements
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[X] Winget installation failed. Please download from https://ollama.com/download/windows" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[+] Ollama is already installed." -ForegroundColor Green
}

# Start Ollama service if not already running
$process = Get-Process ollama -ErrorAction SilentlyContinue
if ($null -eq $process) {
    Write-Host "[*] Starting Ollama server..." -ForegroundColor Cyan
    Start-Process ollama
    Start-Sleep -Seconds 5
}

# Pull lightweight discovery model
Write-Host "[*] Pulling Llama-3 (8B) for local research..." -ForegroundColor Cyan
ollama pull llama3

Write-Host "[+] Local Environment Ready!" -ForegroundColor Green
