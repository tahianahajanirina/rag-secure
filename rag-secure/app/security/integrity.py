# S8 — intégrité par HMAC-SHA256 à clé dédiée, cf. NOTES §3 D11
"""Scellement et vérification d'intégrité des chunks (S8, D11).

Le sceau lie ``texte ‖ doc_sha256 ‖ chunk_index ‖ vecteur`` sous HMAC-SHA256
avec une clé DÉDIÉE (≠ clé de chiffrement pgcrypto, invariant 8) :

  - un SHA-256 nu se recalcule : un attaquant en écriture forgerait une
    empreinte cohérente — le HMAC exige un secret détenu hors base ;
  - la liaison à ``doc_sha256`` + ``chunk_index`` bloque l'attaque par
    échange de lignes (un chunk valide déplacé ailleurs → HMAC invalide) ;
  - le VECTEUR est inclus : stocké en clair (D8) et pilotant la recherche,
    l'omettre laisserait un attaquant modifier le seul ``embedding``
    (HMAC du texte intact → passe) et détourner le retrieval (T3).

Sérialisation du vecteur (CRITIQUE — invariant 8) : octets float32
little-endian via ``struct.pack`` après quantification float32. pgvector
stocke en float32 → le round-trip float32↔float64 est EXACT, donc identique
à l'ingestion et à la relecture. Ne JAMAIS utiliser la forme texte pgvector
(float32→texte→float32 non exact → faux positifs massifs à la lecture).
``_canon_vec`` est LA fonction unique partagée écriture/lecture.

Le SHA-256 nu (``sha256_norm``) ne sert qu'à la déduplication F1
(``documents.doc_sha256``), calculé sur le contexte brut normalisé.

Fonctions pures : aucune dépendance à la base ni au réseau.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import struct
import unicodedata
from typing import Sequence

import numpy as np

# Séparateur d'octets EXPLICITE entre champs (0x1F, « unit separator ») :
# évite toute ambiguïté de concaténation (ex. "ab"+"c" vs "a"+"bc").
_FIELD_SEP = b"\x1f"

_WHITESPACE_RE = re.compile(r"\s+")


def _canon_vec(embedding: Sequence[float] | np.ndarray) -> bytes:
    """Sérialisation canonique du vecteur : octets float32 little-endian.

    UNIQUE point de sérialisation, partagé par ``compute_hmac`` et ``verify``
    (D11). Quantification float32 d'abord (``np.asarray(v, dtype='<f4')``) :
    à la relecture, pgvector renvoie déjà du float32 — la re-quantification
    est alors un no-op, garantissant des octets identiques.
    """
    arr = np.asarray(embedding, dtype="<f4")
    if arr.ndim != 1 or arr.size == 0:
        raise ValueError("embedding : vecteur 1-D non vide attendu")
    # struct.pack sur les valeurs déjà quantifiées float32 → octets exacts.
    return struct.pack(f"<{arr.size}f", *arr.tolist())


def compute_hmac(
    text: str,
    doc_sha256: str,
    chunk_index: int,
    embedding: Sequence[float] | np.ndarray,
    key: bytes,
) -> str:
    """Sceau HMAC-SHA256 (hex) sur ``texte ‖ doc_sha256 ‖ chunk_index ‖ vecteur``.

    ``key`` est la clé d'intégrité DÉDIÉE (``HMAC_KEY_FILE``), jamais la clé
    pgcrypto. Liaison à ``doc_sha256`` (et non ``document_id``, inconnu avant
    l'INSERT — D11).
    """
    if not isinstance(key, (bytes, bytearray)) or len(key) == 0:
        raise ValueError("key : clé HMAC en octets non vide attendue")
    message = _FIELD_SEP.join(
        [
            text.encode("utf-8"),
            doc_sha256.encode("ascii"),
            str(int(chunk_index)).encode("ascii"),
            _canon_vec(embedding),
        ]
    )
    return hmac.new(bytes(key), message, hashlib.sha256).hexdigest()


def verify(
    text: str,
    doc_sha256: str,
    chunk_index: int,
    embedding: Sequence[float] | np.ndarray,
    key: bytes,
    expected: str,
) -> bool:
    """Vérifie le sceau d'un chunk relu (F8/S8) — comparaison à temps constant.

    À appeler à CHAQUE lecture, avec le texte déchiffré ET le vecteur relu
    (D11). Un chunk invalide est exclu du contexte + alerte ``hmac_mismatch``
    (côté appelant, query.py).
    """
    computed = compute_hmac(text, doc_sha256, chunk_index, embedding, key)
    # .strip() : tolère le padding éventuel d'une colonne char(64).
    return hmac.compare_digest(computed, str(expected).strip())


def sha256_norm(text: str) -> str:
    """SHA-256 (hex) du texte NORMALISÉ — déduplication F1 uniquement.

    Normalisation : Unicode NFKC + espaces consécutifs réduits + bords
    retirés. Calculé sur le contexte BRUT, avant pseudonymisation (D11).
    Ce haché n'est PAS une mesure d'intégrité (un SHA nu se recalcule) :
    c'est ``compute_hmac`` qui scelle.
    """
    normalized = _WHITESPACE_RE.sub(" ", unicodedata.normalize("NFKC", text)).strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
