<#
.SYNOPSIS
    Provisionne les modèles Ollama depuis HuggingFace (contournement réseau).

.DESCRIPTION
    À utiliser À LA PLACE du pull d'Ollama (`01_provision.ps1` étape 5 /
    compose.bootstrap.yaml) quand le CDN de stockage d'Ollama (Cloudflare R2)
    est injoignable depuis le réseau. HuggingFace sert les mêmes modèles via
    un CDN AWS qui répond.

    Deux étapes :
      1. télécharge les GGUF depuis HF (conteneur python, reprise + retries) ;
      2. les importe dans Ollama (`ollama create`) sous les noms attendus par
         `.env` : `llama3.2:3b` et `nomic-embed-text` — donc AUCUN changement
         de configuration côté application.

    Prérequis : `01_provision.ps1 -SkipDataset` a déjà tourné (secrets, volume
    `rag_ollama_models`, images) — le pull Ollama a juste échoué. Ce script
    reprend uniquement la partie modèles.

.PARAMETER KeepGguf
    Conserve les GGUF téléchargés dans `gguf_tmp/` (par défaut : supprimés
    après import, car recopiés dans le volume Ollama).
#>
[CmdletBinding()]
param(
    [switch]$KeepGguf
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Volume = "rag_ollama_models"
$GgufDir = Join-Path $Root "gguf_tmp"
$ScriptsDir = $PSScriptRoot

# Garde-fou : le volume doit exister (créé par 01_provision.ps1).
$volExists = docker volume ls --format '{{.Name}}' | Where-Object { $_ -eq $Volume }
if (-not $volExists) {
    throw "Volume $Volume absent. Lancer d'abord scripts/01_provision.ps1 -SkipDataset."
}

New-Item -ItemType Directory -Force -Path $GgufDir | Out-Null

# --- 1. Téléchargement des GGUF depuis HuggingFace ---------------------------
Write-Host "=== [1/2] Téléchargement des GGUF depuis HuggingFace ===" -ForegroundColor Cyan
docker run --rm `
    -v "${GgufDir}:/gguf" `
    -v "${ScriptsDir}:/scripts:ro" `
    python:3.12-slim python /scripts/download_gguf.py
if ($LASTEXITCODE -ne 0) { throw "Échec du téléchargement des GGUF depuis HuggingFace." }

# --- 2. Import dans Ollama (ollama create, local, sans réseau) ---------------
Write-Host "`n=== [2/2] Import dans Ollama (ollama create) ===" -ForegroundColor Cyan

# Script exécuté DANS le conteneur ollama : démarre le démon, attend qu'il
# réponde (ollama list, jamais curl — absent de l'image), crée les 2 modèles
# depuis les GGUF montés, liste, puis s'arrête. Les Modelfile minimaux
# (`FROM <gguf>`) suffisent : Ollama lit le template de chat (llama) et
# détecte l'architecture d'embedding (nomic-bert) depuis les métadonnées GGUF.
$createScript = @'
set -e
ollama serve &
srv=$!
tries=0
until ollama list >/dev/null 2>&1; do
  tries=$((tries + 1))
  [ "$tries" -gt 30 ] && { echo "ollama serve ne repond pas" >&2; exit 1; }
  sleep 2
done
printf 'FROM /gguf/llama.gguf\n' > /tmp/Modelfile.llm
echo "--- creation llama3.2:3b ---"
ollama create llama3.2:3b -f /tmp/Modelfile.llm
printf 'FROM /gguf/nomic.gguf\n' > /tmp/Modelfile.embed
echo "--- creation nomic-embed-text ---"
ollama create nomic-embed-text -f /tmp/Modelfile.embed
echo "--- modeles presents dans le volume ---"
ollama list
kill $srv 2>/dev/null || true
'@

# Écrit le script dans gguf_tmp en LF SANS BOM (c'est un script LINUX exécuté
# dans le conteneur). Les fins de ligne Windows (\r) casseraient le shell
# (« set: Illegal option »). On le lance comme FICHIER (sh /gguf/create.sh),
# plus robuste que « -c <script> » côté passage d'arguments.
$createPath = Join-Path $GgufDir "create.sh"
[System.IO.File]::WriteAllText(
    $createPath, ($createScript -replace "`r", ""),
    (New-Object System.Text.UTF8Encoding($false)))

docker run --rm `
    -v "${Volume}:/root/.ollama" `
    -v "${GgufDir}:/gguf" `
    --entrypoint /bin/sh `
    ollama/ollama:0.9.0 /gguf/create.sh
if ($LASTEXITCODE -ne 0) { throw "Échec de l'import Ollama (ollama create)." }

# --- Nettoyage ---------------------------------------------------------------
if (-not $KeepGguf) {
    Write-Host "`nSuppression des GGUF temporaires (recopiés dans le volume)…" -ForegroundColor Gray
    Remove-Item -Recurse -Force $GgufDir -ErrorAction SilentlyContinue
}

Write-Host "`n=== Modèles provisionnés depuis HuggingFace. ===" -ForegroundColor Green
Write-Host "Étape suivante : scripts/02_up.ps1" -ForegroundColor Gray
