# Notes de conception — Projet RAG sécurisé (DATA707 / BGD707)

Ce fichier complète **`Conception_RAG.drawio`** (7 pages, à ouvrir dans [draw.io](https://app.diagrams.net), l'application de bureau ou l'extension VS Code). Il ne contient que ce qui ne s'exprime pas bien en diagramme : exigences, décisions, droits détaillés, analyse de risque et paramètres.

| Page du .drawio | Contenu |
|---|---|
| 1 · Architecture fonctionnelle | Fonctions F1–F13 (dont F13 consultation d'audit, phase 2), chaînes ingestion / interrogation |
| 2 · Architecture technique | Conteneurs, réseau `internal`, volumes, GPU, cycle P1→P3, DMZ `rag-edge` (phase 2) |
| 3 · Flux d'ingestion | Workflow `ingest.py` avec points de contrôle S* |
| 4 · Flux d'interrogation | Workflow `query.py`, modes `--rag` / `--no-rag` |
| 5 · Modèle de données | Tables `rag.*`, index HNSW, relations |
| 6 · Sécurité | Défense en profondeur : menaces T1–T9 vs couches S1–S9 |
| 7 · Arborescence | Organisation des dossiers/fichiers de l'implémentation |

## 1. Cadrage

**Objectif :** construire un environnement RAG 100 % local (Ollama + PostgreSQL/pgvector + LangChain), le manipuler (ingestion + interrogation), et le durcir selon les principes du module. **Livrables (énoncé) :** PDF unique en français (environnement, procédure d'installation bash, schéma d'architecture, workflow des traitements), scripts Python (stockage + interrogation), tableau de couples prompt/réponse prouvant l'usage de la base. Envoi : à l'enseignant du module.

**Périmètre exclu :** exposition réseau au-delà du loopback durci de la phase 2 (D12), multi-utilisateurs, haute disponibilité, fine-tuning, tout test hors de l'environnement local isolé.

**Contraintes :** travail individuel · hôte Windows 11, ≥ 16 Go RAM, GPU NVIDIA, Docker Desktop (WSL 2) · Internet uniquement en phase P1 (provisioning).

## 2. Exigences

**Fonctionnelles (énoncé) :** EF1 LLM local Ollama (Llama/Gemma) · EF2 base PostgreSQL + pgvector · EF3 script d'upload avec embeddings · EF4 script d'interrogation contextualisée · EF5 orchestration LangChain · EF6 ingestion `neural-bridge/rag-dataset-12000` · EF7 tableau prompt/réponse · EF8 (ajout) mode comparatif avec/sans RAG.

**Sécurité (ajoutées) :**

| ID | Exigence | Rattachement module |
|---|---|---|
| ES1 (→S1) | Isolation : réseau `internal`, 0 port publié | Virtualisation, Cloud |
| ES2 (→S2) | Authentification scram-sha-256, mots de passe par rôle | 4 briques — authentification |
| ES3 (→S3) | Moindre privilège : `rag_ingest` ≠ `rag_reader` | 4 briques — autorisation |
| ES4 (→S4) | Audit pgaudit + journal applicatif JSON | 4 briques — audit |
| ES5 (→S5) | Chiffrement au repos du texte (pgcrypto), clé hors base | 4 briques — chiffrement |
| ES6 (→S6) | Pseudonymisation avant embedding (critères G29) | Anonymisation, RGPD |
| ES7 (→S7) | Anti prompt-injection + anti-poisoning | OWASP LLM01 / LLM04 |
| ES8 (→S8) | Intégrité par **HMAC-SHA256** à clé dédiée, liée au document et à la position, vérifiée à la restitution (D11) | Hachage/MAC, CID |
| ES9 (→S9) | Filtrage des sorties : PII brutes masquées, URLs hors sources neutralisées, jetons de pseudonymisation autorisés et comptés | OWASP LLM02 |
| ES10 | Privacy by design : aucun flux sortant | RGPD, CNIL |

## 3. Décisions (registre)

| ID | Décision | Justification | Alternative écartée |
|---|---|---|---|
| D1 | Docker Desktop (WSL 2), pas de VM imbriquée | GPU natif, pas de double virtualisation ; énoncé : « VM et/ou conteneurs » | VirtualBox + Docker (pas de GPU) |
| D2 | `llama3.1:8b` (q4_K_M) via Ollama GPU ; repli `llama3.2:3b` si VRAM < 6 Go | Recommandé par l'énoncé, bon en français | Gemma 2 9B (équivalent) |
| D3 | Embeddings `nomic-embed-text` (768d) via Ollama | Un seul moteur d'inférence à durcir | sentence-transformers (2ᵉ runtime) |
| D4 | Schéma SQL custom `rag.*`, accès psycopg ; LangChain pour splitter/embeddings/LLM | pgcrypto par colonne, hashes, GRANT fins impossibles avec les tables auto | `langchain_postgres.PGVector` (schéma imposé) |
| D5 | Sous-ensemble ~1 000 contextes (~2 500 chunks) | Suffisant pour la démo, ingestion rapide | Corpus complet (12 000) |
| D6 | `internal: true` après provisioning ; deux fichiers compose distincts (P1/P2) | Preuve structurelle du 100 % local | Pare-feu hôte (moins démontrable) |
| D7 | Rapport : Markdown → PDF | Réutilise la conception ; PDF exigé | LaTeX |
| D8 | pgcrypto sur le texte ; **vecteurs en clair** (contrainte d'indexation pgvector) | Compromis assumé, analysé en §6/T8 | Chiffrement volume seul (moins démontrable) |
| D9 | F2 = hybride **regex (PII à forme) + NER spaCy** `en_core_web_sm` (noms/lieux/orgs), hors-ligne après P1 | Déterminisme et reproductibilité aux frontières de confiance | LLM-détecteur : écarté — composant *instructible* exposé à du contenu non fiable **avant** F3 (surface d'injection) + non-déterminisme |
| D10 | Chunking : récursif 1 000 c / recouvrement 150 en **baseline**, validé par **mini-benchmark empirique** (hit-rate@k sur ~100 questions vérité terrain du dataset, tailles 500/1 000/2 000) — chaque taille ingérée dans un **schéma/base isolé** (sinon collision `doc_sha256 UNIQUE`, et bonne hygiène expérimentale) | La littérature montre qu'il n'y a pas d'optimum universel (dépend corpus + modèle d'embedding) → on mesure sur NOS données | Taille fixe non justifiée ; chunking sémantique/LLM (coût ≫ gain ici, cf. Chroma) |
| D11 | Intégrité S8 : **HMAC-SHA256** sur `texte ‖ doc_sha256 ‖ chunk_index ‖ vecteur`, clé d'intégrité **dédiée** (≠ clé de chiffrement), détenue par rag-app, jamais en base ; SHA-256 nu conservé uniquement pour la déduplication (`doc_sha256`, calculé en F1 sur le contexte brut normalisé) | Un hash public se recalcule : un attaquant en écriture forgerait une empreinte cohérente ; le HMAC exige un secret hors base, et la liaison au document + à la position bloque l'attaque par échange de lignes. **Le vecteur est inclus** car il est stocké en clair (D8) et pilote la recherche : sans lui, un attaquant modifie le seul `embedding` (HMAC du texte intact → passe) et détourne le retrieval (T3, retrieval steering). Liaison à `doc_sha256` et non à `document_id` : l'id est généré par la base **à** l'INSERT, donc inconnu au moment du calcul. Déterminisme : HMAC sur les **octets float32 little-endian** du vecteur (`struct.pack`), round-trip exact float32↔float64 — **et non** sur la forme texte pgvector, fragile (float32→texte→float32 non exact → faux positifs massifs à la lecture) | SHA-256 nu ; HMAC du texte seul (laisse le vecteur manipulable) ; **forme texte du vecteur (fragile)** ; liaison à `document_id` (incalculable avant INSERT) ; signature asymétrique (surdimensionnée, citée en ouverture) |
| D12 | **Phase 2 (optionnelle, après le cœur CLI)** : interface web FastAPI + page HTML minimale — conteneur à double rattachement (`rag-net` internal + `rag-edge` portant l'unique port publié), bind `127.0.0.1:8000` seulement, jeton d'API, validation stricte, plafonds de taille/timeouts, `request_id` corrélant access log ↔ journal applicatif. Option audit : route **`/admin` en lecture seule sur le même port**, jeton admin distinct (séparation des rôles au niveau API) — jamais de port supplémentaire ; l'industrialisation de l'audit (SIEM/ELK) est citée en ouverture | Autorisé par l'énoncé (« scripts a minima ») ; motif DMZ/segmentation du cours ; démos EF7/EF8 plus lisibles ; ajoute l'analyse de risque « exposer un endpoint » au rapport | UI en cœur de projet (risque de retard du livrable exigé) ; pas d'UI (moins de matière démo) ; port dédié à l'audit (surface supplémentaire injustifiée) |
| D13 | Tableau de bord `/admin` (phase 2) : page unique **rendue côté serveur, lecture seule, texte systématiquement échappé, zéro JS externe** — blocs : santé, alertes (HMAC, quarantaine, masquages F11, jetons invalides), activité, agrégats pii_stats ; accès DB via le rôle dédié `rag_auditor` | Une détection que personne ne regarde ne détecte rien (facteur humain) ; l'UI d'audit affiche des chaînes contrôlées par l'attaquant → conçue comme une cible (anti-XSS par échappement) ; les fichiers restent la source de vérité probante | Consultation brute des fichiers seule (irréaliste au quotidien) ; dashboard riche en JS (surface supply-chain injustifiée) |
| D14 | Colonne `chunks.embedding_model` (ex. `nomic-embed-text@v1.5`) épinglant l'espace vectoriel ; garde-fou **à la lecture** (F8 refuse un stock mêlant plusieurs modèles) — la dimension, elle, est déjà figée par le type `vector(768)` | Deux modèles de même dimension produisent des vecteurs incomparables → recherche silencieusement corrompue (écho F5) ; traçabilité de la provenance de chaque vecteur | Confiance implicite en un modèle unique (corruption indétectable si le modèle change) |

## 4. Paramètres retenus

Épinglage de l'espace vectoriel (D14) : colonne `chunks.embedding_model` (ex. `nomic-embed-text@v1.5`) ; à la requête, F8 refuse tout stock mêlant plusieurs modèles (vecteurs d'espaces incompatibles — écho F5). Traçabilité + garde-fou anti-corruption silencieuse de la recherche.

Chunking : `RecursiveCharacterTextSplitter`, 1 000 caractères (≈ 250 tokens, dans la zone 200–400 tokens identifiée comme efficace par l'évaluation Chroma), recouvrement 150 — baseline à confirmer par le mini-benchmark D10. Recherche : distance cosinus, top-k = 4, seuil 0,35 (sous le seuil, aucun contexte n'est injecté). Index : HNSW `vector_cosine_ops`, m = 16, ef_construction = 64. Génération : température 0,1. Dimensions : vector(768). Volumétrie : ~8 Mo d'index (négligeable). Reproductibilité : **graine fixe** pour la sélection (F1) et la génération (F10) ; **préfixes nomic obligatoires** `search_document:` (ingestion) / `search_query:` (requête) ; **`num_ctx = 8192`** forcé côté Ollama (le défaut 2 048 tronque silencieusement le contexte).

## 5. Droits PostgreSQL détaillés (S2/S3)

| Objet | rag_admin (humain, DDL) | rag_ingest (ingest.py) | rag_reader (query.py) |
|---|---|---|---|
| rag.documents | ALL | INSERT, SELECT | SELECT |
| rag.chunks | ALL | INSERT, SELECT | SELECT |
| rag.quarantine | ALL | INSERT | **aucun** (les contenus suspects ne sont jamais restituables par la chaîne de requête) |
| rag.ingest_log | ALL | INSERT | SELECT |
| DDL / extensions | oui | non | non |

Complément : `REVOKE ALL ON SCHEMA public FROM PUBLIC` ; `pg_hba.conf` limité au sous-réseau Docker en scram-sha-256 ; mots de passe distincts par rôle, stockés dans `secrets/`, jamais versionnés. Audit : `pgaudit.log = 'write, ddl'` global + `'read'` pour `rag_reader` ; `log_connections = on`.

**Phase 2 (D13)** : 4ᵉ rôle **`rag_auditor`** pour la route `/admin` — SELECT sur `ingest_log` ; **GRANT par colonne** sur `quarantine` (`source_ref, reason, score, detected_at` — jamais `content_enc`) ; **GRANT par colonne** sur `documents` (`pii_stats, source_ref, ingested_at` — pour les agrégats du tableau, jamais de contenu) ; aucun droit sur `chunks`. Le moindre privilège descend jusqu'à la colonne.

## 6. Menaces et risques résiduels

| ID | Menace | Bloquée par | Statut |
|---|---|---|---|
| T1 | Exfiltration (egress, télémétrie) | S1 | couvert |
| T2 | Accès non autorisé à la base | S2, S3, S4 | couvert |
| T3 | RAG poisoning à l'ingestion ou en base | S7 (quarantaine), S8, S4 | couvert |
| T4 | Injection de prompt indirecte via documents | S7 (spotlighting), S9 | couvert (défense en profondeur, heuristiques contournables) |
| T5 | Fuite de PII dans les réponses | S6, S9 | couvert |
| T6 | Vol des données au repos | S5 + BitLocker hôte | couvert |
| T7 | Élévation de privilège applicative | S3 | couvert |
| T8 | Inversion / extraction d'embeddings | — | **résiduel accepté** : pgvector impose les vecteurs en clair pour indexer ; corpus public et pseudonymisé en amont ; pistes citées dans le rapport : contrôle d'accès strict (fait), chiffrement volume, recherche chiffrée / homomorphe (écho au cours) |
| T9 | Exposition du point d'accès web (phase 2, D12) | bind 127.0.0.1 + réseau `rag-edge` séparé (DMZ) + jeton d'API + validation et plafonds | couvert si l'UI est activée |

Autres résiduels à mentionner : clé pgcrypto sur le même hôte (pas de HSM — cf. cours Cloud), confiance dans les images officielles (épinglage par digest, scan mentionné).

## 7. Démonstrations et critères d'acceptation

1. **RAG prouvé (EF7/EF8)** : ≥ 5 questions dont la réponse est dans le corpus → correcte avec `--rag`, incorrecte/évasive avec `--no-rag`.
2. **S1** : test d'egress sortant depuis chaque conteneur → échec réseau attendu — **via l'interpréteur présent dans l'image, pas `curl`** (absent de `python:3.12-slim` et de l'image `ollama` : un `curl` échouerait faute d'outil = faux positif). Pour `rag-app` : `docker exec rag-app python -c "import urllib.request; urllib.request.urlopen('https://example.com', timeout=5)"` → on attend une `URLError`/échec DNS (= isolé). Plus `docker network inspect rag-net` → `"Internal": true` ; `docker ps` → aucun port publié (hors `127.0.0.1:8000` en phase 2).
3. **S2** : connexion avec mauvais mot de passe → rejet, tracé dans les logs.
4. **S3** : `INSERT` sous `rag_reader` → `permission denied`, tracé pgaudit.
5. **S5** : `SELECT content_enc` brut → bytea illisible sans clé.
6. **S6** : document factice avec email/téléphone → jetons en base + `pii_stats`.
7. **S7/S8** : document piégé factice → quarantaine ; chunk altéré manuellement (UPDATE) → HMAC invalide détecté, chunk exclu ; injection forcée dans un corpus de test → réponse non détournée (spotlighting).
8. *(phase 2)* **T9** : appel API sans jeton ou jeton invalide → 401 + trace dans l'access log ; `/admin` inaccessible avec le jeton de requête (séparation des jetons).

Toutes les démonstrations ont lieu dans l'environnement local isolé, sur données factices ou publiques.

## 8. Correspondance avec le module

Fondations SSI (CID par bien, prévention/détection/réaction) · 4 briques Big Data (S2–S5 sur la base de connaissances) · anonymisation G29 (S6 : individualisation, corrélation, inférence discutées dans le rapport) · cryptographie (AES/pgcrypto, SHA-256, gestion de clé, ouverture homomorphe) · cloud & virtualisation (conteneurs, isolation, HSM en résiduel) · RGPD/CNIL (traitement local, minimisation) · sécurité de l'IA (OWASP LLM Top 10 : LLM01, LLM02, LLM04, LLM08).

## 9. Statut

- [x] Conception validée (diagrammes + présentes notes) — revue page par page, 2026-07-03
- [ ] Implémentation démarrée (`Projet/RAG/rag-secure/`, cf. page 7)
