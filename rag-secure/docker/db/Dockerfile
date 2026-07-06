# ============================================================================
# rag-db — PostgreSQL 17 + pgvector + pgaudit (D4, S2–S5)
# ----------------------------------------------------------------------------
# Base : image officielle pgvector (PostgreSQL 17 + extension vector).
# Ajout : postgresql-17-pgaudit pour l'audit des accès (S4).
# Les hooks /docker-entrypoint-initdb.d/* s'exécutent en ordre alphanumérique
# au PREMIER démarrage (volume pg_data vierge) :
#   01_roles.sh   → rôles applicatifs (AUCUN GRANT table-level ici)
#   02_schema.sql → extensions + schéma rag.* + index HNSW
#   03_grants.sql → droits (APRÈS création des tables)
#   04_audit.sql  → pgaudit par rôle
# ============================================================================
FROM pgvector/pgvector:pg17

# pgaudit (S4) — paquet Debian PGDG correspondant à PostgreSQL 17
RUN apt-get update \
    && apt-get install -y --no-install-recommends postgresql-17-pgaudit \
    && rm -rf /var/lib/apt/lists/*

# Configurations durcies (scram-sha-256, pgaudit, log_parameter=off — S4/S5)
# Référencées par la `command:` du service (compose.yaml) :
#   postgres -c config_file=/etc/postgresql/postgresql.conf \
#            -c hba_file=/etc/postgresql/pg_hba.conf
COPY postgresql.conf /etc/postgresql/postgresql.conf
COPY pg_hba.conf /etc/postgresql/pg_hba.conf

# Hooks d'initialisation (ordre alphanumérique = ordre d'exécution, SPEC §3.1)
COPY initdb/ /docker-entrypoint-initdb.d/
RUN chmod 0755 /docker-entrypoint-initdb.d/01_roles.sh
