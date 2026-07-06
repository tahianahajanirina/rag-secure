<#
.SYNOPSIS
    P2 — Exploitation : démarre la stack en réseau FERMÉ (S1). SPEC §3.6.

.DESCRIPTION
    Phase 1 (défaut) : rag-db + rag-ollama + rag-app (idle), rag-net internal,
    AUCUN port publié.
    Phase 2 (-Phase2) : ajoute l'override compose.phase2.yaml — l'API tourne
    (uvicorn) et l'UNIQUE port 127.0.0.1:8000 est publié.

    Prérequis : scripts/01_provision.ps1 exécuté (secrets, volume, modèles,
    dataset). Ce script ne télécharge rien.

.PARAMETER Phase2
    Active l'API web + la DMZ rag-edge (D12).

.PARAMETER Down
    Arrête et supprime la stack (docker compose down) au lieu de la démarrer.
#>
[CmdletBinding()]
param(
    [switch]$Phase2,
    [switch]$Down
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

# Fichiers compose : base + override phase 2 si demandé.
$composeArgs = @("-f", "compose.yaml")
if ($Phase2) { $composeArgs += @("-f", "compose.phase2.yaml") }

if ($Down) {
    Write-Host "=== Arrêt de la stack ===" -ForegroundColor Cyan
    docker compose @composeArgs down
    exit $LASTEXITCODE
}

# Garde-fous : le provisioning doit avoir eu lieu.
if (-not (Test-Path (Join-Path $Root "secrets/pg_admin_pw"))) {
    throw "Secrets absents. Lancer d'abord scripts/01_provision.ps1."
}
if (-not (Test-Path (Join-Path $Root ".env"))) {
    throw ".env absent. Lancer d'abord scripts/01_provision.ps1."
}
$volume = docker volume ls --format '{{.Name}}' | Where-Object { $_ -eq "rag_ollama_models" }
if (-not $volume) {
    throw "Volume rag_ollama_models absent. Lancer d'abord scripts/01_provision.ps1."
}

$phaseLabel = if ($Phase2) { "phase 2 (API + rag-edge)" } else { "phase 1 (CLI seule)" }
Write-Host "=== P2 exploitation — $phaseLabel ===" -ForegroundColor Cyan

docker compose @composeArgs up -d
if ($LASTEXITCODE -ne 0) { throw "Échec du démarrage." }

Write-Host "`nAttente des healthchecks (db, ollama)…" -ForegroundColor Yellow
docker compose @composeArgs ps

Write-Host "`n=== Stack démarrée. ===" -ForegroundColor Green
Write-Host "Ingestion   : docker exec rag-app python ingest.py --n-docs 1000" -ForegroundColor Gray
Write-Host "Requête     : docker exec rag-app python query.py `"Your question?`" --rag --show-sources" -ForegroundColor Gray
if ($Phase2) {
    Write-Host "API         : http://127.0.0.1:8000/  (jeton dans secrets/api_token)" -ForegroundColor Gray
    Write-Host "Audit       : http://127.0.0.1:8000/admin  (jeton dans secrets/admin_token)" -ForegroundColor Gray
}
Write-Host "Vérif. S1   : scripts/03_verify_isolation.ps1" -ForegroundColor Gray
