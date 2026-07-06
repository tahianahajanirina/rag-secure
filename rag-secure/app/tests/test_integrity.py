"""Tests de security.integrity (S8, D11) — SPEC §4.

Cas exigés par la definition of done :
  - round-trip compute/verify valide ;
  - détection d'altération de CHAQUE champ scellé, dont le cas critique
    « SEUL le vecteur est modifié » (D11 — anti retrieval steering T3) ;
  - round-trip float32↔float64 qui DOIT rester valide (sérialisation
    canonique float32 : pgvector relit en float32, l'appli calcule souvent
    en float64 — le sceau doit être identique des deux côtés).
"""

from __future__ import annotations

import numpy as np
import pytest

from security.integrity import _canon_vec, compute_hmac, sha256_norm, verify

KEY = b"cle-hmac-de-test-32-octets-minimum!!"
OTHER_KEY = b"une-autre-cle-hmac-differente-!!!!!!"
DOC_SHA = "a" * 64
TEXT = "Le contenu pseudonymisé d'un chunk, avec accents éàü."
VEC = [0.1, -0.2, 0.30000001, 4.5e-3, -1.0, 0.0, 123.456, -7.89]


def test_round_trip_valide():
    seal = compute_hmac(TEXT, DOC_SHA, 3, VEC, KEY)
    assert len(seal) == 64  # hex SHA-256
    assert verify(TEXT, DOC_SHA, 3, VEC, KEY, seal)


def test_round_trip_float32_float64_reste_valide():
    """CRITIQUE (D11) : sceller depuis du float64 puis vérifier depuis le
    float32 relu de pgvector (et inversement) doit passer — la quantification
    float32 canonique rend les deux formes identiques octet à octet."""
    vec_f64 = np.asarray(VEC, dtype=np.float64)
    # Simule le stockage pgvector : quantification float32 à l'écriture…
    vec_f32 = vec_f64.astype(np.float32)
    # …puis relecture (souvent re-promue en float64 par du code numérique).
    vec_f64_relu = vec_f32.astype(np.float64)

    seal = compute_hmac(TEXT, DOC_SHA, 0, vec_f64, KEY)
    assert verify(TEXT, DOC_SHA, 0, vec_f32, KEY, seal)
    assert verify(TEXT, DOC_SHA, 0, vec_f64_relu, KEY, seal)
    # La sérialisation canonique est bien identique pour les trois formes.
    assert _canon_vec(vec_f64) == _canon_vec(vec_f32) == _canon_vec(vec_f64_relu)


def test_seul_le_vecteur_modifie_invalide_le_sceau():
    """CRITIQUE (D11/T3) : altérer UNIQUEMENT l'embedding — texte, document et
    position intacts — doit invalider le HMAC (sinon : retrieval steering)."""
    seal = compute_hmac(TEXT, DOC_SHA, 3, VEC, KEY)
    vec_altere = list(VEC)
    vec_altere[0] += 1e-3  # altération minime mais réelle en float32
    assert not verify(TEXT, DOC_SHA, 3, vec_altere, KEY, seal)


def test_alteration_de_chaque_champ_detectee():
    seal = compute_hmac(TEXT, DOC_SHA, 3, VEC, KEY)
    assert not verify(TEXT + ".", DOC_SHA, 3, VEC, KEY, seal)          # texte
    assert not verify(TEXT, "b" * 64, 3, VEC, KEY, seal)               # document
    assert not verify(TEXT, DOC_SHA, 4, VEC, KEY, seal)                # position (échange de lignes)
    assert not verify(TEXT, DOC_SHA, 3, VEC, OTHER_KEY, seal)          # clé


def test_sceau_depend_de_la_cle():
    """Un attaquant sans la clé dédiée ne peut pas forger un sceau cohérent."""
    assert compute_hmac(TEXT, DOC_SHA, 0, VEC, KEY) != compute_hmac(
        TEXT, DOC_SHA, 0, VEC, OTHER_KEY
    )


def test_padding_char64_tolere():
    """psycopg peut renvoyer un char(64) avec padding : verify le tolère."""
    seal = compute_hmac(TEXT, DOC_SHA, 1, VEC, KEY)
    assert verify(TEXT, DOC_SHA, 1, VEC, KEY, seal + "  ")


def test_canon_vec_rejette_les_formes_invalides():
    with pytest.raises(ValueError):
        _canon_vec([])
    with pytest.raises(ValueError):
        _canon_vec([[0.1, 0.2], [0.3, 0.4]])  # 2-D
    with pytest.raises(ValueError):
        compute_hmac(TEXT, DOC_SHA, 0, VEC, b"")  # clé vide


def test_sha256_norm_normalise_espaces_et_unicode():
    """Déduplication F1 : mêmes contenus aux blancs/formes Unicode près →
    même empreinte ; contenus réellement différents → empreintes distinctes."""
    a = sha256_norm("Le  chat \n mange.")
    b = sha256_norm("Le chat mange.")
    assert a == b
    # NFKC : « ﬁ » (ligature U+FB01) ≡ « fi »
    assert sha256_norm("ﬁchier") == sha256_norm("fichier")
    assert sha256_norm("Le chat mange.") != sha256_norm("Le chien mange.")
