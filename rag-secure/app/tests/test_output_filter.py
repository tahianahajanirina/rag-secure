"""Tests de security.output_filter (S9/F11) — SPEC §4.

Exigé : PII brute masquée VS jeton de pseudonymisation laissé passer.
Complété par : neutralisation des URLs hors sources, conservation des URLs
autorisées, comptage des flags.
"""

from __future__ import annotations

from security.output_filter import filter_output, has_masking


def test_email_brut_masque():
    answer = "You can reach the author at jane.doe@corp.com for details."
    filtered, flags = filter_output(answer, set())
    assert "jane.doe@corp.com" not in filtered
    assert "[EMAIL_MASQUE]" in filtered
    assert flags["masked"] == {"EMAIL": 1}
    assert has_masking(flags)


def test_jeton_pseudonymisation_laisse_passer_et_compte():
    """Les jetons S6 ([EMAIL_1]…) sont la preuve du pipeline : ils passent."""
    answer = "The message from [EMAIL_1] mentioned [PERSON_2] twice: [PERSON_2]."
    filtered, flags = filter_output(answer, set())
    assert filtered == answer  # aucune altération
    assert flags["tokens_passed"] == {"EMAIL": 1, "PERSON": 2}
    assert not has_masking(flags)


def test_masquage_et_jetons_dans_la_meme_reponse():
    answer = "Contact [EMAIL_1] — leaked copy: real.leak@evil.org"
    filtered, flags = filter_output(answer, set())
    assert "[EMAIL_1]" in filtered
    assert "real.leak@evil.org" not in filtered
    assert flags["tokens_passed"] == {"EMAIL": 1}
    assert flags["masked"] == {"EMAIL": 1}


def test_telephone_et_ip_masques():
    answer = "Call +1 555 123 4567 or ping 10.0.0.42 directly."
    filtered, flags = filter_output(answer, set())
    assert "[PHONE_MASQUE]" in filtered and "[IP_MASQUE]" in filtered
    assert flags["masked"] == {"IP": 1, "PHONE": 1}


def test_url_hors_sources_neutralisee():
    answer = "More details at https://phishing.example/steal?q=data ."
    filtered, flags = filter_output(answer, {"rag12000:7"})
    assert "phishing.example" not in filtered
    assert "[URL_NEUTRALISEE]" in filtered
    assert flags["urls_neutralized"] == 1
    assert has_masking(flags)


def test_url_presente_dans_les_sources_conservee():
    url = "https://en.wikipedia.org/wiki/Retrieval"
    answer = f"See {url} for background."
    filtered, flags = filter_output(answer, {url, "rag12000:7"})
    assert url in filtered
    assert flags["urls_neutralized"] == 0


def test_url_autorisee_tolere_ponctuation_finale():
    """Le modèle colle souvent « . » ou « / » à l'URL : comparaison canonique."""
    answer = "See https://site.example/page/."
    filtered, flags = filter_output(answer, {"https://site.example/page"})
    assert flags["urls_neutralized"] == 0
    assert "site.example/page" in filtered


def test_reponse_saine_inchangee():
    answer = "The Great Wall is over 21,000 km long [source: rag12000:3]."
    filtered, flags = filter_output(answer, {"rag12000:3"})
    assert filtered == answer
    assert not has_masking(flags)
