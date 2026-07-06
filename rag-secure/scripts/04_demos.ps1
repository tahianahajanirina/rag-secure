<#
.SYNOPSIS
    Rejoue les 8 démonstrations des critères d'acceptation (NOTES §7). SPEC §3.6.

.DESCRIPTION
    Orchestrateur mince : la logique base/sécurité est dans app/demos.py
    (réutilise les vraies chaînes). Ce script :
      1. S1 : appelle 03_verify_isolation.ps1 (egress, ports, internal) ;
      2. S2/S3/S5/S6/S7/S8 + EF7/EF8 : docker exec rag-app python demos.py ;
      3. T9 (si -Phase2) : tests API (jeton absent/invalide → 401 ;
         /admin refusé avec le jeton de requête) ;
      4. copie les fragments produits (/logs) vers resultats/.

    Prérequis : stack démarrée (02_up.ps1) ET ingestion faite
    (docker exec rag-app python ingest.py --n-docs …) pour S5 et EF7/EF8.

.PARAMETER Phase2
    Ajoute les démonstrations T9 (API). La stack doit tourner en phase 2.

.PARAMETER NQuestions
    Nombre de couples question/réponse du tableau EF7/EF8 (défaut 6, ≥5 requis).
#>
[CmdletBinding()]
param(
    [switch]$Phase2,
    [int]$NQuestions = 6
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Results = Resolve-Path (Join-Path $Root "..\resultats")
$Logs = Join-Path $Root "logs"

Write-Host "=== Démonstrations de sécurité (NOTES §7) ===" -ForegroundColor Cyan

# --- 1. S1 : isolation réseau ------------------------------------------------
Write-Host "`n[1/4] S1 — isolation réseau…" -ForegroundColor Yellow
& (Join-Path $PSScriptRoot "03_verify_isolation.ps1") -Phase2:$Phase2

# --- 2. S2/S3/S5/S6/S7/S8 + EF7/EF8 via demos.py -----------------------------
Write-Host "`n[2/4] S2–S8 + tableau EF7/EF8 (app/demos.py)…" -ForegroundColor Yellow
docker exec rag-app python demos.py --all --n-questions $NQuestions
if ($LASTEXITCODE -ne 0) {
    Write-Warning ("demos.py a renvoyé un code non nul — vérifier que la stack " +
        "tourne et que l'ingestion a été faite (S5/EF7 requièrent des données).")
}

# --- 3. T9 : API (phase 2 seulement) -----------------------------------------
$t9Lines = New-Object System.Collections.Generic.List[string]
if ($Phase2) {
    Write-Host "`n[3/4] T9 — sécurité de l'API (phase 2)…" -ForegroundColor Yellow
    $t9Lines.Add("## Démo T9 — exposition de l'API (phase 2)")
    $t9Lines.Add("")
    $base = "http://127.0.0.1:8000"
    $apiToken = (Get-Content (Join-Path $Root "secrets\api_token") -Raw).Trim()

    function Invoke-Probe {
        param([string]$Label, [hashtable]$Headers, [string]$Path = "/query")
        $body = @{ question = "test"; mode = "no-rag" } | ConvertTo-Json -Compress
        try {
            $r = Invoke-WebRequest -Uri "$base$Path" -Method Post -Headers $Headers `
                -ContentType "application/json" -Body $body -UseBasicParsing
            return @{ Code = $r.StatusCode; Ok = $true }
        } catch {
            $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { -1 }
            return @{ Code = $code; Ok = $false }
        }
    }

    # a) /query sans jeton → 401
    $r = Invoke-Probe -Label "sans jeton" -Headers @{}
    $t9Lines.Add("- /query **sans jeton** → HTTP $($r.Code) (attendu 401)")

    # b) /query jeton invalide → 401
    $r = Invoke-Probe -Headers @{ "X-API-Token" = "jeton-bidon" }
    $t9Lines.Add("- /query **jeton invalide** → HTTP $($r.Code) (attendu 401)")

    # c) /health sans jeton → 200
    try {
        $h = Invoke-WebRequest -Uri "$base/health" -UseBasicParsing
        $t9Lines.Add("- /health sans jeton → HTTP $($h.StatusCode) (attendu 200)")
    } catch { $t9Lines.Add("- /health → erreur : $($_.Exception.Message)") }

    # d) /admin avec le jeton de REQUÊTE (pas admin) → 401 (séparation des jetons)
    try {
        $a = Invoke-WebRequest -Uri "$base/admin" -Headers @{ "X-Admin-Token" = $apiToken } `
            -UseBasicParsing
        $t9Lines.Add("- /admin avec le **jeton de requête** → HTTP $($a.StatusCode) (ANORMAL : attendu 401)")
    } catch {
        $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { -1 }
        $t9Lines.Add("- /admin avec le **jeton de requête** → HTTP $code (attendu 401 : jetons distincts)")
    }
    $t9Lines.Add("")
    Write-Host ($t9Lines -join "`n")
} else {
    Write-Host "`n[3/4] T9 ignoré (phase 1). Relancer avec -Phase2 après 02_up.ps1 -Phase2." -ForegroundColor Gray
}

# --- 4. Consolidation des résultats ------------------------------------------
Write-Host "`n[4/4] Consolidation vers resultats/…" -ForegroundColor Yellow

# demos.py écrit dans /logs (le conteneur monte ./logs) → visibles côté hôte.
$appFragment = Join-Path $Logs "demos_securite_app.md"
$tableauFragment = Join-Path $Logs "tableau_prompt_reponse.md"

# Le compte rendu S1 (demos_securite.md) a été écrit par 03_verify_isolation.
# On y APPEND les fragments applicatifs + T9.
$demoReport = Join-Path $Results "demos_securite.md"
if (Test-Path $appFragment) {
    Add-Content -Path $demoReport -Value "`r`n" -Encoding utf8
    # -Encoding UTF8 obligatoire : le fragment est écrit par Python en UTF-8
    # SANS BOM ; sans ce flag, PS 5.1 le lirait en ANSI (accents cassés).
    Add-Content -Path $demoReport -Value (Get-Content $appFragment -Raw -Encoding UTF8) -Encoding utf8
}
if ($t9Lines.Count -gt 0) {
    Add-Content -Path $demoReport -Value "`r`n" -Encoding utf8
    Add-Content -Path $demoReport -Value ($t9Lines -join "`r`n") -Encoding utf8
}

if (Test-Path $tableauFragment) {
    Copy-Item $tableauFragment (Join-Path $Results "tableau_prompt_reponse.md") -Force
    Write-Host "  tableau_prompt_reponse.md mis à jour"
}

Write-Host "`n=== Démonstrations terminées. Résultats dans $Results ===" -ForegroundColor Green
Write-Host "  - demos_securite.md (S1–S8" -NoNewline
if ($Phase2) { Write-Host " + T9)" } else { Write-Host ")" }
Write-Host "  - tableau_prompt_reponse.md (EF7/EF8)"
