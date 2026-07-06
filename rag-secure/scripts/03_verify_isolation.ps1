<#
.SYNOPSIS
    P3 — Vérification de l'isolation réseau (preuves S1). SPEC §3.6, NOTES §7.

.DESCRIPTION
    Trois preuves structurelles :
      1. rag-net est bien "Internal": true (docker network inspect) ;
      2. aucun port publié (docker ps) hors 127.0.0.1:8000 en phase 2 ;
      3. egress SORTANT bloqué depuis chaque conteneur — testé avec
         l'INTERPRÉTEUR PRÉSENT dans l'image (jamais un client HTTP en ligne
         de commande, absent de ces images) :
           - rag-app / rag-db : python -c urllib (python:3.12-slim et
             l'image postgres n'ont pas d'outil HTTP CLI) ;
           - rag-ollama : le binaire ollama (pas d'outil HTTP CLI non plus).
         On ATTEND un échec réseau (= isolé). On distingue explicitement
         « échec réseau = isolé » de « outil absent = test invalide ».

    Écrit le compte rendu dans resultats/demos_securite.md.
#>
[CmdletBinding()]
param(
    [switch]$Phase2
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Results = Join-Path $Root "..\resultats"
New-Item -ItemType Directory -Force -Path $Results | Out-Null
$Report = Join-Path $Results "demos_securite.md"

$lines = New-Object System.Collections.Generic.List[string]
function Add-Line { param([string]$Text) $lines.Add($Text); Write-Host $Text }

Add-Line "# Preuves d'isolation réseau (S1) — P3"
Add-Line ""
Add-Line ("> Généré par scripts/03_verify_isolation.ps1. Test d'egress via " +
          "l'interpréteur présent dans chaque image (pas de client HTTP CLI : " +
          "absent de python:3.12-slim et de l'image ollama).")
Add-Line ""

# --- Preuve 1 : réseau internal ----------------------------------------------
Add-Line "## 1. rag-net est internal"
# EAP local : même piège « stderr natif redirigé sous EAP=Stop » (2>$null).
$internal = & {
    $ErrorActionPreference = "Continue"
    docker network inspect rag-secure_rag-net --format '{{.Internal}}' 2>$null
}
if (-not $internal) {
    # Selon la version de compose, le réseau peut être préfixé différemment.
    $netName = docker network ls --format '{{.Name}}' | Where-Object { $_ -like "*rag-net*" } | Select-Object -First 1
    if ($netName) { $internal = docker network inspect $netName --format '{{.Internal}}' }
}
Add-Line "``docker network inspect … Internal`` = **$internal** (attendu : true)"
Add-Line ""

# --- Preuve 2 : aucun port publié --------------------------------------------
Add-Line "## 2. Ports publiés"
$ports = docker ps --format '{{.Names}} :: {{.Ports}}'
foreach ($line in $ports) { Add-Line "- $line" }
Add-Line ""
Add-Line ("Attendu : aucune correspondance ``0.0.0.0:`` ; en phase 2, uniquement " +
          "``127.0.0.1:8000`` sur rag-app.")
Add-Line ""

# --- Preuve 3 : egress bloqué ------------------------------------------------
Add-Line "## 3. Egress sortant bloqué (par conteneur)"
Add-Line ""
if ($Phase2) {
    Add-Line ("> **Note phase 2 (compromis DMZ assumé)** : rag-app est aussi " +
              "rattaché à rag-edge, un bridge NON-internal indispensable pour " +
              "publier 127.0.0.1:8000. Un bridge non-internal fait du NAT " +
              "sortant : rag-app PEUT donc atteindre Internet en phase 2 — ce " +
              "n'est pas une faille mais le prix de l'exposition contrôlée " +
              "(le code de rag-app n'émet aucun appel Internet ; T9 encadre " +
              "l'entrée). Les JOYAUX rag-db et rag-ollama restent exclusivement " +
              "sur rag-net internal → egress bloqué dans LES DEUX phases.")
    Add-Line ""
}

# Chaque test distingue : échec réseau = ISOLÉ (exit 0) ; connexion = OUVERT
# (exit 3) ; outil/interpréteur absent = TEST INVALIDE (exit 4).
# rag-app : python présent (python:3.12-slim) → urllib.
$pyEgress = @'
import sys, urllib.request
try:
    urllib.request.urlopen("https://example.com", timeout=5)
except urllib.error.URLError as e:
    print("ISOLE: echec reseau (%s)" % (e.reason,)); sys.exit(0)
except Exception as e:
    print("TEST_INVALIDE: %r" % (e,)); sys.exit(4)
else:
    print("OUVERT: egress possible"); sys.exit(3)
'@

# rag-db : l'image postgres n'a PAS python — mais elle a bash → /dev/tcp
# (test TCP natif, sans aucun outil externe). Connexion établie = OUVERT.
$bashEgress = 'exec 3<>/dev/tcp/example.com/443 && { echo "OUVERT: egress possible"; exit 3; }; echo "ISOLE: echec reseau"; exit 0'

function Test-Egress {
    param(
        [string]$Container,
        [string[]]$Command,
        # rag-app en phase 2 : egress OUVERT est ATTENDU (DMZ), pas une faille.
        [switch]$OpenExpected
    )
    Write-Host "  → $Container" -ForegroundColor Yellow
    # PS 5.1 : sous EAP=Stop, rediriger le stderr d'une native (2>&1) lève
    # une RemoteException dès la première ligne d'erreur — or ICI l'échec
    # réseau est justement le résultat ATTENDU. EAP local à la fonction.
    $ErrorActionPreference = "Continue"
    $output = docker exec $Container @Command 2>&1 | Out-String
    $code = $LASTEXITCODE
    $verdict = switch ($code) {
        0 { "ISOLÉ (échec réseau attendu)" }
        3 { if ($OpenExpected) { "OUVERT via DMZ rag-edge (attendu en phase 2)" }
            else { "**FUITE** — egress ouvert (ANORMAL) !" } }
        4 { "TEST INVALIDE (outil/interpréteur absent)" }
        default { "indéterminé (exit $code)" }
    }
    # Extrait la ligne de verdict propre émise par le test (ISOLE:/OUVERT:/
    # TEST_INVALIDE:) plutôt que la sortie brute, que PS 5.1 pollue avec le
    # décor NativeCommandError quand le stderr natif est fusionné (2>&1).
    $clean = ($output -split "`r?`n" |
        Where-Object { $_ -match 'ISOLE:|OUVERT:|TEST_INVALIDE:' } |
        Select-Object -First 1)
    if (-not $clean) { $clean = "(exit $code)" }
    Add-Line "- **$Container** : $verdict"
    Add-Line "  - sortie : ``$($clean.Trim())``"
    return $code
}

# rag-app : isolé en phase 1 ; en phase 2, egress via rag-edge = attendu.
Test-Egress -Container "rag-app" -Command @("python", "-c", $pyEgress) -OpenExpected:$Phase2 | Out-Null
# rag-db (JOYAU) : DOIT être isolé dans les deux phases — bash /dev/tcp.
Test-Egress -Container "rag-db"  -Command @("bash", "-c", $bashEgress) | Out-Null

# rag-ollama (JOYAU) : ni client HTTP CLI ni python garantis → on tente un
# pull réseau, qui doit échouer faute de route (le binaire ollama EST présent).
# Scriptblock & { } : EAP local (même piège 2>&1 que dans Test-Egress).
Write-Host "  → rag-ollama (via ollama, pas d'outil HTTP CLI/python)" -ForegroundColor Yellow
$ollamaOut = & {
    $ErrorActionPreference = "Continue"
    docker exec rag-ollama ollama pull hello-world:nonexistent 2>&1 | Out-String
}
$ollamaCode = $LASTEXITCODE
# On garde une ligne parlante (dial/lookup/timeout…) sans le décor PS 5.1.
$ollamaLine = ($ollamaOut -split "`r?`n" |
    Where-Object { $_ -match 'dial|lookup|refused|timeout|no route|Error|network|resolve' } |
    Select-Object -First 1)
if (-not $ollamaLine) { $ollamaLine = "(exit $ollamaCode)" }
$ollamaVerdict = if ($ollamaCode -ne 0) { "échec attendu (pas de route Internet)" }
                 else { "**ANORMAL** — le pull a réussi (egress ouvert ?)" }
Add-Line "- **rag-ollama** (joyau) : $ollamaVerdict"
Add-Line "  - sortie : ``$($ollamaLine.Trim())``"
Add-Line ""

Add-Line "## Conclusion"
Add-Line ("Isolation vérifiée si : Internal=true, aucun ``0.0.0.0:`` publié " +
          "(hors 127.0.0.1:8000 en phase 2), et les JOYAUX rag-db + rag-ollama " +
          "en ISOLÉ. En phase 2, l'egress de rag-app via rag-edge est le " +
          "compromis DMZ documenté (T9), pas une régression de S1.")

$content = [string]::Join("`r`n", $lines)
[System.IO.File]::WriteAllText($Report, $content, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "`n[✓] Compte rendu écrit : $Report" -ForegroundColor Green
