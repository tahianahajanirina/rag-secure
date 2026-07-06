#!/usr/bin/env bash
# ============================================================================
# 01_roles.sh — Création des rôles applicatifs (S2/S3, D13 — SPEC §3.1)
# ----------------------------------------------------------------------------
# Script SHELL (et non .sql) : seul un hook shell peut LIRE les fichiers
# secrets (*_FILE) — un .sql pur est passé tel quel à psql et ne peut pas.
#
# Exécuté par l'entrypoint de l'image postgres au premier démarrage,
# SOUS L'IDENTITÉ du superutilisateur bootstrap POSTGRES_USER=rag_admin
# (créé par l'image elle-même via POSTGRES_PASSWORD_FILE — SPEC §2.1).
# → rag_admin n'est PAS créé ici, et il est propriétaire de tout ce que
#   font les hooks suivants (02_schema.sql notamment).
#
# Ce script ne fait QUE :
#   1. créer rag_ingest, rag_reader, rag_auditor (mots de passe lus des *_FILE)
#   2. REVOKE ALL ON SCHEMA public FROM PUBLIC
# Aucun droit table-level ici : les tables n'existent pas encore (elles
# arrivent en 02) ; les droits sont dans 03_grants.sql (ordre des hooks).
#
# Pas d'idempotence CREATE ROLE : les hooks initdb ne s'exécutent qu'une
# seule fois, sur un volume pg_data vierge.
# ============================================================================
set -euo pipefail

# --- Vérification des secrets : existants ET non vides ----------------------
# Une initialisation à moitié faite est pire qu'un échec net (SPEC §3.1).
for var in PG_INGEST_PASSWORD_FILE PG_READER_PASSWORD_FILE PG_AUDITOR_PASSWORD_FILE; do
    file="${!var:-}"
    if [ -z "${file}" ]; then
        echo "ERREUR 01_roles.sh : variable ${var} non définie" >&2
        exit 1
    fi
    if [ ! -s "${file}" ]; then
        echo "ERREUR 01_roles.sh : fichier secret ${file} absent ou vide (${var})" >&2
        exit 1
    fi
done

# Lecture des mots de passe — $(cat …) retire les fins de ligne finales,
# cohérent avec config.read_secret() côté Python (strip).
ingest_pw="$(cat "${PG_INGEST_PASSWORD_FILE}")"
reader_pw="$(cat "${PG_READER_PASSWORD_FILE}")"
auditor_pw="$(cat "${PG_AUDITOR_PASSWORD_FILE}")"

# --- Création des rôles ------------------------------------------------------
# Les mots de passe passent par des VARIABLES psql (-v) citées :'var' —
# jamais interpolés dans le texte SQL, jamais écrits dans un fichier.
psql -v ON_ERROR_STOP=1 \
     -v ingest_pw="${ingest_pw}" \
     -v reader_pw="${reader_pw}" \
     -v auditor_pw="${auditor_pw}" \
     --username "${POSTGRES_USER}" --dbname "${POSTGRES_DB}" <<'EOSQL'
-- Rôles applicatifs : LOGIN seul, aucun attribut d'administration (S3).
CREATE ROLE rag_ingest  LOGIN PASSWORD :'ingest_pw'  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
CREATE ROLE rag_reader  LOGIN PASSWORD :'reader_pw'  NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
CREATE ROLE rag_auditor LOGIN PASSWORD :'auditor_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;

-- Fermeture du schéma public : rien pour PUBLIC (NOTES §5).
REVOKE ALL ON SCHEMA public FROM PUBLIC;
EOSQL

echo "01_roles.sh : rôles rag_ingest, rag_reader, rag_auditor créés."
