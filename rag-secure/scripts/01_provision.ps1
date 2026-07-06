<#
.SYNOPSIS
    P1 — Provisioning (Internet requis, UNE SEULE FOIS). SPEC §3.6.

.DESCRIPTION
    Ordre (SPEC §3.6) :
      1. vérifie les prérequis (Docker, GPU) ;
      2. gen_secrets : crée les 8 fichiers de ./secrets s'ils manquent
         (aléatoire cryptographique, permissions restreintes) ;
      3. crée le volume externe partagé rag_ollama_models ;
      4. build des images (le modèle spaCy est cuit dans l'image app au build) ;
      5. pull des deux modèles Ollama dans le volume (compose.bootstrap) ;
      6. download_dataset.py (côté hôte).

    Idempotent : les secrets et le volume existants ne sont pas recréés.
    Ce script NE lance PAS l'exploitation (voir 02_up.ps1).

.PARAMETER NDocs
    Nombre de contextes du dataset à télécharger (défaut 1000, D5).

.PARAMETER SkipDataset
    Ne pas (re)télécharger le dataset (utile si ./data est déjà peuplé).
#>
[CmdletBinding()]
param(
    [int]$NDocs = 1000,
    [switch]$SkipDataset
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Racine du projet = parent du dossier scripts/
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Secrets = Join-Path $Root "secrets"
$DataDir = Join-Path $Root "data"
$EnvFile = Join-Path $Root ".env"
$VolumeName = "rag_ollama_models"

Write-Host "=== P1 provisioning (racine : $Root) ===" -ForegroundColor Cyan

# --- 1. Prérequis ------------------------------------------------------------
Write-Host "`n[1/6] Vérification des prérequis…" -ForegroundColor Yellow
# NB PS 5.1 : une commande NATIVE qui échoue ne déclenche PAS try/catch —
# le verdict fiable est $LASTEXITCODE (un catch ne voit que « exécutable
# introuvable »).
try { docker version --format '{{.Server.Version}}' | Out-Null }
catch { throw "Docker introuvable (exécutable absent). Installer Docker Desktop (WSL 2)." }
if ($LASTEXITCODE -ne 0) {
    throw "Le démon Docker ne répond pas. Démarrer Docker Desktop et attendre « Engine running »."
}
Write-Host "  Docker : OK"

# GPU NVIDIA (repli documenté au README si absent → llama3.2:3b).
# Verdict par $LASTEXITCODE (cf. note ci-dessus) ; stderr laissé visible.
$gpuNames = docker run --rm --gpus all nvidia/cuda:12.4.0-base-ubuntu22.04 `
    nvidia-smi --query-gpu=name --format=csv,noheader
if ($LASTEXITCODE -eq 0 -and $gpuNames) {
    $gpuNames | ForEach-Object { Write-Host "  GPU : $_" }
} else {
    Write-Warning ("GPU NVIDIA non détecté par Docker. Le RAG fonctionnera sur CPU " +
        "(lent) ou basculer LLM_MODEL=llama3.2:3b dans .env (README §Dépannage).")
}

# --- 2. .env + gen_secrets ----------------------------------------------------
Write-Host "`n[2/6] Configuration et secrets…" -ForegroundColor Yellow
if (-not (Test-Path $EnvFile)) {
    Copy-Item (Join-Path $Root ".env.example") $EnvFile
    Write-Host "  .env créé depuis .env.example"
} else {
    Write-Host "  .env déjà présent (conservé)"
}

New-Item -ItemType Directory -Force -Path $Secrets | Out-Null

function New-RandomSecret {
    <# Secret aléatoire cryptographique. -AsHex pour les clés binaires
       (pgcrypto/HMAC) ; sinon base64 URL-safe pour les mots de passe.
       NB : Create().GetBytes() — la méthode statique Fill() n'existe pas
       en .NET Framework (PowerShell 5.1). #>
    param([int]$Bytes = 32, [switch]$AsHex)
    $buffer = New-Object 'System.Byte[]' $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($buffer) } finally { $rng.Dispose() }
    if ($AsHex) { return -join ($buffer | ForEach-Object { $_.ToString("x2") }) }
    return [Convert]::ToBase64String($buffer).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

# 8 secrets (SPEC §2.2). Générés seulement s'ils manquent (idempotent).
#   *_pw          : mots de passe des rôles + jetons API/admin (base64)
#   pgcrypto_key  : clé de chiffrement S5
#   hmac_key      : clé d'intégrité S8, DISTINCTE (invariant 8) — hex
$secretSpecs = @(
    @{ Name = "pg_admin_pw";   Hex = $false },
    @{ Name = "pg_ingest_pw";  Hex = $false },
    @{ Name = "pg_reader_pw";  Hex = $false },
    @{ Name = "pg_auditor_pw"; Hex = $false },
    @{ Name = "pgcrypto_key";  Hex = $true  },
    @{ Name = "hmac_key";      Hex = $true  },
    @{ Name = "api_token";     Hex = $false },
    @{ Name = "admin_token";   Hex = $false }
)
foreach ($spec in $secretSpecs) {
    $path = Join-Path $Secrets $spec.Name
    if (Test-Path $path) {
        Write-Host "  secret $($spec.Name) : déjà présent (conservé)"
        continue
    }
    $value = New-RandomSecret -Bytes 32 -AsHex:$spec.Hex
    # Sans BOM et SANS retour de ligne final : le fichier ne contient QUE le
    # secret (cohérent avec config.read_secret() qui .strip(), et $(cat) shell).
    [System.IO.File]::WriteAllText($path, $value, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "  secret $($spec.Name) : généré"
}

# Permissions restreintes sur ./secrets (utilisateur courant seul).
try {
    icacls $Secrets /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F" | Out-Null
    Write-Host "  permissions restreintes appliquées à ./secrets"
} catch {
    Write-Warning "  impossible de durcir les ACL de ./secrets : $($_.Exception.Message)"
}

# --- 3. Volume modèles partagé -----------------------------------------------
Write-Host "`n[3/6] Volume des modèles Ollama…" -ForegroundColor Yellow
$existing = docker volume ls --format '{{.Name}}' | Where-Object { $_ -eq $VolumeName }
if ($existing) {
    Write-Host "  volume $VolumeName : déjà présent"
} else {
    docker volume create $VolumeName | Out-Null
    Write-Host "  volume $VolumeName : créé"
}

# --- 4. Build des images ------------------------------------------------------
Write-Host "`n[4/6] Build des images (db, app + spaCy au build)…" -ForegroundColor Yellow
docker compose -f compose.yaml build
if ($LASTEXITCODE -ne 0) {
    throw ("Échec du build. Conflit de dépendances pip probable : voir README " +
           "§Dépannage (réinstallation propre + pip freeze).")
}

# --- 5. Pull des modèles ------------------------------------------------------
Write-Host "`n[5/6] Téléchargement des modèles Ollama (~5 Go)…" -ForegroundColor Yellow
docker compose -f compose.bootstrap.yaml run --rm bootstrap-models
if ($LASTEXITCODE -ne 0) { throw "Échec du pull des modèles Ollama." }

# --- 6. Dataset --------------------------------------------------------------
Write-Host "`n[6/6] Dataset…" -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
if ($SkipDataset) {
    Write-Host "  -SkipDataset : téléchargement ignoré"
} else {
    $subset = Join-Path $DataDir "rag_subset.jsonl"
    $seed = 42
    Write-Host "  python scripts/download_dataset.py --n $NDocs --seed $seed"
    python (Join-Path $PSScriptRoot "download_dataset.py") --n $NDocs --seed $seed --out $subset
    if ($LASTEXITCODE -ne 0) {
        throw ("Échec du téléchargement du dataset. Prérequis hôte : " +
               "pip install datasets (README §Prérequis).")
    }
}

Write-Host "`n=== P1 terminé. Étape suivante : scripts/02_up.ps1 ===" -ForegroundColor Green
