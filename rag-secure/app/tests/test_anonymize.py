"""Tests de security.anonymize (S6, D9) — SPEC §4.

Exigé : pseudonymisation EMAIL / PHONE / IP + un cas NER.

Les cas regex passent par ``find_regex_pii`` (pur, sans spaCy) ET par
``pseudonymize`` quand le modèle NER est disponible. Les cas nécessitant
spaCy/en_core_web_sm sont SKIPPÉS proprement s'il manque (hôte nu) — dans
l'image rag-app le modèle est cuit au build et tout s'exécute.
"""

from __future__ import annotations

import pytest

from security.anonymize import TOKEN_RE, find_regex_pii, pseudonymize


def _categories(text: str, **kwargs) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for _s, _e, category, value in find_regex_pii(text, **kwargs):
        found.setdefault(category, []).append(value)
    return found


def _ner_disponible() -> bool:
    try:
        import spacy

        spacy.load("en_core_web_sm")
        return True
    except Exception:
        return False


requiert_ner = pytest.mark.skipif(
    not _ner_disponible(),
    reason="spaCy/en_core_web_sm absent (installé au build de l'image rag-app ; "
    "sur l'hôte : README §Tests)",
)


# --- Détection regex (pure, sans NER) -----------------------------------------

def test_detecte_email():
    found = _categories("Contact John at john.doe+test@example.co.uk please.")
    assert found["EMAIL"] == ["john.doe+test@example.co.uk"]


def test_detecte_telephone():
    found = _categories("Call me at +33 6 12 34 56 78 or (555) 123-4567.")
    assert len(found["PHONE"]) == 2


def test_detecte_ip_valide_et_ignore_invalide():
    found = _categories("Server 192.168.1.10 responded; 999.999.999.999 is not an IP.")
    assert found["IP"] == ["192.168.1.10"]


def test_detecte_iban():
    found = _categories("Wire to FR76 3000 6000 0112 3456 7890 189 today.")
    assert "IBAN" in found and found["IBAN"][0].startswith("FR76")


def test_url_nominative_detectee_url_neutre_ignoree():
    text = (
        "See https://site.example/users/jdupont for the author "
        "and https://site.example/docs/guide for the manual."
    )
    found = _categories(text)
    urls = found.get("URL", [])
    assert any("/users/jdupont" in u for u in urls)
    assert not any("/docs/guide" in u for u in urls)


def test_une_date_iso_nest_pas_un_telephone():
    assert "PHONE" not in _categories("Published on 2024-01-15, revised 2025 03 02.")


def test_email_dans_url_nominative_un_seul_span():
    found = _categories("Profile: https://ex.org/profile/x?email=a@b.com")
    assert "URL" in found and "EMAIL" not in found  # l'URL englobe l'email


# --- Pseudonymisation complète (NER requis) --------------------------------------

@requiert_ner
def test_pseudonymise_email_phone_ip():
    text = "Email jane@corp.com or 192.168.0.1, phone +1 555 123 4567."
    pseudo, stats = pseudonymize(text)
    assert "jane@corp.com" not in pseudo
    assert "192.168.0.1" not in pseudo
    assert "[EMAIL_1]" in pseudo and "[IP_1]" in pseudo and "[PHONE_1]" in pseudo
    assert stats["EMAIL"] == 1 and stats["IP"] == 1 and stats["PHONE"] == 1


@requiert_ner
def test_cas_ner_personne():
    """Cas NER exigé par le SPEC : un nom de personne devient [PERSON_n]."""
    text = "Barack Obama visited Paris and met the team of Microsoft."
    pseudo, stats = pseudonymize(text)
    assert "Obama" not in pseudo
    assert stats.get("PERSON", 0) >= 1
    assert TOKEN_RE.search(pseudo)


@requiert_ner
def test_numerotation_coherente_par_document():
    """Même valeur → même jeton ; valeurs distinctes → numéros distincts."""
    text = "Write to a@x.com and b@y.com; a@x.com is preferred."
    pseudo, stats = pseudonymize(text)
    assert pseudo.count("[EMAIL_1]") == 2
    assert pseudo.count("[EMAIL_2]") == 1
    assert stats["EMAIL"] == 3


@requiert_ner
def test_texte_sans_pii_inchange():
    text = "It measures 330 meters and was finished on time."
    pseudo, stats = pseudonymize(text)
    assert pseudo == text
    assert stats == {}
