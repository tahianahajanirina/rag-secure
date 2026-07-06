# Environnement RAG sécurisé

RAG (*Retrieval-Augmented Generation*) **100 % local et durci**, construit pour le module
**DATA707 — Sécurité pour le Big Data** (Télécom Paris, IP Paris). Déployé et **exécuté de
bout en bout** : chaque mesure de sécurité est démontrée sur machine réelle, preuves à l'appui.

> Un LLM local répond à des questions en s'appuyant sur un corpus vectorisé — sans qu'aucune
> donnée ne quitte la machine, sans qu'aucune donnée personnelle n'entre dans un vecteur, et
> sans qu'un document piégé puisse détourner la chaîne.

## Architecture

Trois conteneurs Docker sur un réseau **fermé** (`internal: true`, zéro port publié) :

| Conteneur | Rôle | Image |
|---|---|---|
| `rag-app` | ingestion, interrogation, API web (Python non-root, code en lecture seule) | `python:3.12-slim` |
| `rag-db` | stockage vectoriel + audit | `pgvector/pgvector:pg17` + pgaudit |
| `rag-ollama` | LLM (`llama3.2:3b`) + embeddings (`nomic-embed-text`, 768d) | `ollama/ollama` |

Orchestration **LangChain**, accès SQL explicite **psycopg** (requêtes paramétrées uniquement).
Cycle de vie en 3 phases : **P1** provisionnement (seul moment avec Internet) → **P2**
exploitation en vase clos → **P3** vérification de l'isolation. Une phase 2 optionnelle expose
une interface web FastAPI **bornée à `127.0.0.1:8000`** via une DMZ dédiée.

## Mesures de sécurité

| # | Mesure | Mise en œuvre |
|---|---|---|
| S1 | Isolation réseau | réseau `internal`, egress bloqué, 0 port publié (loopback seul en phase 2) |
| S2 | Authentification | `scram-sha-256`, un mot de passe par rôle, secrets montés en fichiers |
| S3 | Moindre privilège | 4 rôles PostgreSQL, `GRANT` jusqu'à la colonne, `REVOKE … PUBLIC` |
| S4 | Audit | pgaudit (`log_parameter=off` : aucune clé dans les journaux) + journal JSON applicatif |
| S5 | Chiffrement au repos | `pgcrypto` sur le texte des chunks, clé hors base |
| S6 | Pseudonymisation | regex + NER spaCy **avant** tout embedding — aucune PII dans un vecteur |
| S7 | Anti-injection | heuristiques déterministes à l'ingestion (quarantaine) + *spotlighting* du prompt |
| S8 | Intégrité | HMAC-SHA256 à clé dédiée scellant `texte ‖ hash doc ‖ index ‖ vecteur` |
| S9 | Filtrage des sorties | masquage des PII résiduelles, neutralisation des URLs hors sources |

Deux partis pris notables : le **vecteur est inclus dans le sceau HMAC** (sinon un attaquant
modifierait le seul embedding pour détourner le retrieval sans casser l'empreinte), et **aucun
LLM n'est employé comme détecteur de sécurité** (un composant instructible exposé à du contenu
non fiable serait lui-même une surface d'injection).

## Démarrage rapide

Prérequis : Windows + Docker Desktop (WSL 2). Le runbook complet (P1→P3, dépannage) est dans
[`rag-secure/README.md`](rag-secure/README.md).

```powershell
cd rag-secure
.\scripts\01_provision.ps1        # P1 : images, modèles, dataset, secrets (Internet requis)
.\scripts\02_up.ps1               # P2 : démarrage sur réseau fermé
docker exec rag-app python ingest.py --n-docs 200
docker exec rag-app python query.py "Ma question ?" --rag --show-sources
.\scripts\03_verify_isolation.ps1 # P3 : preuve d'isolation
.\scripts\02_up.ps1 -Phase2       # option : interface web sur 127.0.0.1:8000
```

Tests unitaires (sans Docker) : `pytest app/tests/` — 42 tests couvrant les 5 modules `security/`.

## Structure du dépôt

```
├── conception/     design validé : diagramme 7 planches + notes (exigences, décisions, menaces)
├── SPEC.md         manifeste de build (contrats transverses, fichier par fichier)
├── rag-secure/     tout le code : compose, SQL d'init, app Python, scripts P1-P3, tests
├── resultats/      preuves d'exécution : démonstrations S1-S9 + T9, tableau prompt/réponse
└── rapport/        rapport final (PDF 3 pages + source), figures et captures réelles
```

## Résultats

Sur le dataset public `neural-bridge/rag-dataset-12000` : 197 documents ingérés (909 chunks
chiffrés et scellés), 4 862 entités personnelles pseudonymisées, 3 documents réels mis en
quarantaine par la garde anti-injection. Avec RAG, les réponses sont correctes et sourcées ;
sans RAG, le modèle hallucine avec assurance — la comparaison chiffrée est dans
[`resultats/tableau_prompt_reponse.md`](resultats/tableau_prompt_reponse.md) et le détail des
démonstrations dans [`resultats/demos_securite.md`](resultats/demos_securite.md).

---

*Projet académique individuel — Télécom Paris, juillet 2026. Environnement isolé, données
factices ou publiques uniquement.*
