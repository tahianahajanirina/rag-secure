# Benchmark chunking (D10) — hit-rate@k mesuré

<!-- GABARIT — écrasé par app/benchmark_chunking.py (via docker exec). Justifie
     CHUNK_SIZE par la MESURE, pas par défaut (NOTES §3 D10). -->

- Modèle d'embedding : `nomic-embed-text@v1.5` (préfixes nomic)
- k = 4 · recouvrement constant = 150 · documents = _(n)_ · graine = 42
- Hit = le document d'origine (`doc_sha256`) apparaît dans le top-k brut (avant seuil).

| Taille (car.) | Chunks | Questions | Hit-rate@k | Similarité moy. des hits | Ingestion (s) | Requête moy. (ms) |
|---:|---:|---:|---:|---:|---:|---:|
| 500 | _(à remplir)_ | | | | | |
| 1000 | | | | | | |
| 2000 | | | | | | |

**Lecture** _(à compléter)_ : retenir la taille au meilleur hit-rate@k ;
confirmer/ajuster `CHUNK_SIZE` dans `.env` d'après ce tableau. La baseline de
conception est 1000 caractères (≈ 250 tokens, zone efficace Chroma).

## Procédure de génération

```powershell
# Stack démarrée (02_up.ps1). Chaque taille est ingérée dans un schéma isolé
# rag_bench_<taille> (rôle rag_admin), puis les schémas sont supprimés.
docker exec rag-app python benchmark_chunking.py --n-docs 200 --n-questions 100
# docker cp — pas `>` (PowerShell 5.1 réencoderait en UTF-16)
docker cp rag-app:/logs/benchmark_chunking.md resultats\benchmark_chunking.md
```
