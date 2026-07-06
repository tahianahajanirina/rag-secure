# RAG sécurisé — runbook (DATA707 / BGD707)

Environnement RAG **100 % local** et durci : Ollama (LLM + embeddings) +
PostgreSQL 17/pgvector + LangChain, en conteneurs Docker sur un réseau
`internal`. Cadre strictement académique et défensif ; données factices ou
publiques ; environnement isolé.

> Ce dépôt contient **le code et la procédure**. Les modèles (~5 Go), le
> dataset et les secrets ne sont **pas** versionnés : ils sont produits en
> phase P1 sur votre machine. Internet n'est requis **qu'en P1**.

## Sommaire

- [Prérequis](#prérequis)
- [Cycle de vie P1 → P2 → P3](#cycle-de-vie)
- [P1 — Provisioning](#p1--provisioning-internet)
- [P2 — Exploitation](#p2--exploitation-réseau-fermé)
- [Ingestion & interrogation](#ingestion--interrogation)
- [P3 — Vérification de l'isolation](#p3--vérification-de-lisolation)
- [Phase 2 — API web + audit](#phase-2--api-web--audit)
- [Démonstrations & benchmark](#démonstrations--benchmark)
- [Tests unitaires](#tests-unitaires-sans-docker)
- [Architecture de sécurité (résumé)](#architecture-de-sécurité-résumé)
- [Dépannage](#dépannage)

---

## Prérequis

| Élément | Détail |
|---|---|
| OS | Windows 11, ≥ 16 Go RAM |
| GPU | NVIDIA (repli CPU / `llama3.2:3b` possible, cf. dépannage) |
| Docker | Docker Desktop avec backend **WSL 2** et intégration GPU |
| Python hôte | Python 3.10+ **uniquement** pour télécharger le dataset en P1 : `pip install datasets` |
| Chiffrement disque | BitLocker recommandé (défense S5 + T6) |

Vérifier l'accès GPU depuis Docker :

```powershell
docker run --rm --gpus all nvidia/cuda:12.4.0-base-ubuntu22.04 nvidia-smi
```

> Tout se lance depuis le dossier `rag-secure/`. Les scripts PowerShell y font
> référence en relatif : ouvrez un terminal **dans `rag-secure/`**.

---

## Cycle de vie

```
P1 provisioning   → P2 exploitation      → P3 vérification
(Internet, 1 fois)  (réseau internal)      (preuves d'isolation)
build images        compose up             egress KO, 0 port publié,
pull modèles        ingestion, requêtes    docker network inspect
dataset, secrets    démos
```

Deux fichiers compose distincts matérialisent la coupure réseau (D6) :
`compose.bootstrap.yaml` (P1, réseau ouvert, pull des modèles) et
`compose.yaml` (P2, `rag-net` **internal**, aucun port publié).

---

## P1 — Provisioning (Internet)

```powershell
# Depuis rag-secure/
.\scripts\01_provision.ps1 -NDocs 1000
```

Ce script (idempotent) :

1. vérifie Docker + GPU ;
2. crée `.env` depuis `.env.example` **et génère les 8 secrets** dans
   `.\secrets\` (mots de passe des 4 rôles, clé pgcrypto **S5**, clé HMAC
   **S8** distincte, jetons API/admin) — aléatoire cryptographique,
   permissions restreintes ;
3. crée le volume partagé `rag_ollama_models` ;
4. **build** les images (`rag-db`, `rag-app` — le modèle spaCy `en_core_web_sm`
   est cuit dans l'image au build) ;
5. **pull** `llama3.1:8b` + `nomic-embed-text` dans le volume ;
6. télécharge le dataset (`neural-bridge/rag-dataset-12000`, sous-ensemble
   déterministe) dans `.\data\`.

> **Épingler `EMBED_MODEL_TAG` (D14).** Après le pull, relevez l'identité
> réelle du modèle d'embedding et reportez-la dans `.env` si besoin :
>
> ```powershell
> docker compose -f compose.bootstrap.yaml run --rm --entrypoint ollama bootstrap-models show nomic-embed-text
> ```
>
> La valeur par défaut `nomic-embed-text@v1.5` est indicative ; elle doit
> refléter le modèle servi (elle est écrite dans `chunks.embedding_model` et
> vérifiée à la lecture — un stock mêlant deux tags est refusé).

---

## P2 — Exploitation (réseau fermé)

```powershell
.\scripts\02_up.ps1            # phase 1 : rag-db + rag-ollama + rag-app (idle)
```

Attendez que les healthchecks passent (`docker compose ps` → `healthy`).
`rag-app` reste vivant (commande idle) pour être piloté par `docker exec`.

Arrêt : `.\scripts\02_up.ps1 -Down`.

---

## Ingestion & interrogation

```powershell
# Ingestion sécurisée (F1–F6) — rôle rag_ingest
docker exec rag-app python ingest.py --n-docs 1000

# Interrogation contextualisée (F7–F12) — rôle rag_reader
docker exec rag-app python query.py "What is the Great Wall of China?" --rag --show-sources

# Mode comparatif EF8 (sans contexte)
docker exec rag-app python query.py "What is the Great Wall of China?" --no-rag
```

Chaîne d'ingestion : déduplication SHA-256 → **pseudonymisation** (S6, avant
tout embedding) → **garde anti-injection** (S7, quarantaine si suspect) →
chunking → embeddings (préfixe `search_document:`) → **HMAC** scellant le
vecteur (S8) + **chiffrement** pgcrypto (S5) → insertion transactionnelle.

Chaîne de requête : embedding `search_query:` → **garde D14** (un seul modèle)
→ top-k cosinus (`similarité = 1 − distance`, seuil 0,35) → **vérification
HMAC** de chaque chunk → **prompt durci** (spotlighting, S7) → génération
(`num_ctx=8192`, `temperature=0.1`, graine) → **filtrage de sortie** (S9).

Les journaux applicatifs JSON sont dans `.\logs\app.jsonl` ; les traces
pgaudit dans `docker logs rag-db`.

---

## P3 — Vérification de l'isolation

```powershell
.\scripts\03_verify_isolation.ps1
```

Produit `..\resultats\demos_securite.md` avec trois preuves : `rag-net` est
`Internal: true`, aucun port publié, egress sortant **bloqué** depuis chaque
conteneur. Le test d'egress utilise l'interpréteur présent dans l'image
(`python -c urllib` ; **jamais** `curl`, absent de `python:3.12-slim` et de
l'image `ollama`) : on attend un **échec réseau** = isolé.

---

## Phase 2 — API web + audit

```powershell
.\scripts\02_up.ps1 -Phase2     # override : uvicorn + DMZ rag-edge, port 127.0.0.1:8000
```

- Interface question : <http://127.0.0.1:8000/> — jeton dans `secrets\api_token`.
- Tableau d'audit : <http://127.0.0.1:8000/admin> — jeton **distinct** dans
  `secrets\admin_token`.
- Sonde : <http://127.0.0.1:8000/health> (sans jeton).

Le service n'écoute que sur le **loopback de l'hôte** (S1/D12). Durcissement :
jetons distincts comparés à temps constant, validation Pydantic stricte,
`TrustedHostMiddleware`, CSP sans origine externe, aucun CORS permissif,
sortie `/admin` intégralement échappée (anti-XSS, D13).

Exemple d'appel :

```powershell
$token = (Get-Content .\secrets\api_token -Raw).Trim()
Invoke-RestMethod -Uri http://127.0.0.1:8000/query -Method Post `
  -Headers @{ "X-API-Token" = $token } -ContentType "application/json" `
  -Body (@{ question = "What is the Great Wall of China?"; mode = "rag" } | ConvertTo-Json)
```

---

## Démonstrations & benchmark

```powershell
# 8 démonstrations des critères d'acceptation (NOTES §7)
.\scripts\04_demos.ps1                 # S1–S8 + tableau EF7/EF8
.\scripts\04_demos.ps1 -Phase2         # ajoute T9 (API) — stack en phase 2

# Benchmark de chunking (D10) — justifie CHUNK_SIZE par la mesure
docker exec rag-app python benchmark_chunking.py --n-docs 200 --n-questions 100
# docker cp (copie fidèle) — surtout pas `>` : en PowerShell 5.1, la
# redirection réencoderait le fichier en UTF-16.
docker cp rag-app:/logs/benchmark_chunking.md ..\resultats\benchmark_chunking.md
```

`04_demos.ps1` remplit `..\resultats\demos_securite.md` et
`..\resultats\tableau_prompt_reponse.md`. Prérequis : stack démarrée **et**
ingestion faite (S5 et EF7/EF8 nécessitent des données en base).

---

## Livrable final — PDF + figures

Le rendu à envoyer est un **PDF unique en français** (`rapport/rapport.md` →
`rapport/rapport_final.pdf`).

**1. Exporter les 7 figures du diagramme.** Ouvrir
`conception/Conception_RAG.drawio` dans [draw.io](https://app.diagrams.net)
(ou l'app de bureau). Pour **chaque** page (menu des onglets en bas) :
*Fichier → Exporter en → PNG…*, enregistrer dans `rapport/figures/` sous les
noms attendus par le rapport :
`page1_fonctionnelle.png`, `page2_technique.png`, `page3_ingestion.png`,
`page4_interrogation.png`, `page5_donnees.png`, `page6_securite.png`,
`page7_arborescence.png`.

**2. Compléter le rapport.** Insérer le tableau EF7/EF8 (§9, depuis
`resultats/tableau_prompt_reponse.md`) et coller au besoin les extraits de
`resultats/demos_securite.md`. Les valeurs déjà mesurées (volumétrie, S1–S9)
sont pré-remplies.

**3. Générer le PDF.** Le plus simple (VS Code est installé) :
- Installer l'extension **« Markdown PDF » (yzane)** dans VS Code.
- Ouvrir `rapport/rapport.md`, clic droit dans l'éditeur →
  **« Markdown PDF: Export (pdf) »**. Le PDF est créé à côté du `.md`
  (images incluses).

Alternative en ligne de commande (si `pandoc` + un moteur LaTeX sont installés) :
```powershell
pandoc rapport\rapport.md -o rapport\rapport_final.pdf --pdf-engine=xelatex -V lang=fr
```

---

## Tests unitaires (sans Docker)

Les 5 modules `security/` sont des fonctions pures, testables sur l'hôte :

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install pytest numpy spacy
python -m spacy download en_core_web_sm      # pour les tests NER (sinon skippés)
pytest app\tests\ -v
```

Lancer un seul module ou un seul cas :

```powershell
pytest app\tests\test_integrity.py -v
pytest app\tests\test_integrity.py -k float32 -v
```

Les tests couvrant le NER spaCy sont **skippés proprement** si le modèle n'est
pas installé ; tout le reste (regex PII, injection, intégrité HMAC dont le cas
« vecteur seul modifié » et le round-trip float32, spotlighting, filtrage)
s'exécute sans dépendance externe.

---

## Architecture de sécurité (résumé)

| Couche | Mesures | Menaces couvertes |
|---|---|---|
| Isolation (S1) | `rag-net` internal, 0 port publié (phase 2 : 127.0.0.1 seul) | T1, T9 |
| Base (S2–S5) | scram-sha-256, 4 rôles moindre privilège, pgaudit, pgcrypto | T2, T6, T7 |
| Données & LLM (S6–S9) | pseudonymisation, anti-injection, HMAC, filtrage sortie | T3, T4, T5 |

4 rôles PostgreSQL : `rag_admin` (DDL), `rag_ingest` (ingestion),
`rag_reader` (requête, lecture seule), `rag_auditor` (`/admin`, GRANT par
colonne). Clés **distinctes** pour le chiffrement (pgcrypto) et l'intégrité
(HMAC), montées en lecture seule dans `rag-app`, **jamais** en base ni dans un
journal. Détails : `..\conception\NOTES_conception.md` et `..\SPEC.md`.

---

## Dépannage

| Symptôme | Cause probable / correctif |
|---|---|
| **Build pip échoue** (résolution de dépendances) | Épingles `requirements.txt` incompatibles. Réinstaller proprement **sans versions** puis figer : `pip install langchain langchain-text-splitters langchain-ollama "psycopg[binary]" pgvector numpy pydantic spacy fastapi uvicorn pytest && pip freeze > docker\app\requirements.txt`. Attention au plafond `numpy<2` de certaines dépendances. |
| **GPU non détecté** | Vérifier l'intégration GPU de Docker Desktop (WSL 2). Repli : `LLM_MODEL=llama3.2:3b` dans `.env` (VRAM < 6 Go). Sur CPU, l'inférence fonctionne mais est lente. |
| **`docker exec rag-app …` : « is not running »** | `rag-app` a besoin d'un process long. En phase 1 il est idle (`tail -f`) ; vérifier `docker compose ps`. |
| **Réponses tronquées / hors sujet** | `NUM_CTX` doit valoir 8192 (le défaut Ollama 2048 tronque le contexte silencieusement). |
| **Modèle spaCy introuvable** (hors conteneur) | `python -m spacy download en_core_web_sm`. Dans l'image il est déjà cuit au build. |
| **Requête refusée « stock mêlant plusieurs modèles »** (D14) | Le corpus a été indexé avec un `embedding_model` différent de `EMBED_MODEL_TAG`. Ré-indexer entièrement, ou corriger `.env`. |
| **Les modèles pullés en P1 semblent absents en P2** | Le volume `rag_ollama_models` doit être le **même** (externe, nommé) dans les deux compose. Le recréer via P1 si besoin. |
| **`.ps1` : erreurs de syntaxe étranges / accents cassés** | Les scripts sont en UTF-8 **avec BOM** (requis par Windows PowerShell 5.1). Ne pas les réenregistrer sans BOM. Sinon, exécuter avec `pwsh` (PowerShell 7). |
| **PowerShell bloque l'exécution des scripts** | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` dans le terminal courant. |

---

*Aucune donnée personnelle réelle n'est utilisée. Toutes les démonstrations
ont lieu dans l'environnement local isolé.*
