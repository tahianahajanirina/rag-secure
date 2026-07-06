"""Télécharge les GGUF des modèles depuis HuggingFace (contournement réseau).

Le CDN de stockage d'Ollama (Cloudflare R2) est injoignable depuis certains
réseaux (route ISP défaillante). HuggingFace sert les mêmes modèles via un CDN
AWS (`us.aws.cdn.hf.co`) qui, lui, répond. Ce script télécharge les deux GGUF
avec **reprise sur coupure** (requêtes Range) et retries — robuste sur une
connexion instable.

Tourne dans un conteneur `python:3.12-slim` (cf. bootstrap_hf.ps1), écrit dans
`/gguf` (bind mount hôte). Les modèles sont ensuite importés dans Ollama par
`ollama create` (étape locale, sans réseau).
"""

from __future__ import annotations

import os
import sys
import time
import urllib.error
import urllib.request

OUT_DIR = "/gguf"

# Fichiers locaux → URL HuggingFace (résolus vers us.aws.cdn.hf.co).
MODELS = {
    "llama.gguf": (
        "https://huggingface.co/bartowski/Llama-3.2-3B-Instruct-GGUF/"
        "resolve/main/Llama-3.2-3B-Instruct-Q4_K_M.gguf"
    ),
    "nomic.gguf": (
        "https://huggingface.co/nomic-ai/nomic-embed-text-v1.5-GGUF/"
        "resolve/main/nomic-embed-text-v1.5.f16.gguf"
    ),
}

CHUNK = 1 << 20         # 1 Mo
MAX_ATTEMPTS = 60       # tolérant à une connexion très instable
TIMEOUT = 120


def total_size(url: str) -> int:
    """Taille totale via une requête Range 0-0 (Content-Range : .../TOTAL)."""
    req = urllib.request.Request(url, headers={"Range": "bytes=0-0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        content_range = resp.headers.get("Content-Range", "")
        if "/" in content_range:
            return int(content_range.rsplit("/", 1)[-1])
        return int(resp.headers.get("Content-Length", 0))


def download(name: str, url: str) -> None:
    dest = os.path.join(OUT_DIR, name)
    size = total_size(url)
    host = url.split("/")[2]
    print(f"--- {name} : {size / 1e6:.0f} Mo depuis {host} ---", flush=True)

    for attempt in range(1, MAX_ATTEMPTS + 1):
        have = os.path.getsize(dest) if os.path.exists(dest) else 0
        if have >= size > 0:
            print(f"[OK] {name} complet ({have / 1e6:.0f} Mo)", flush=True)
            return
        try:
            req = urllib.request.Request(url, headers={"Range": f"bytes={have}-"})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                # Si le serveur ignore Range (200 au lieu de 206) : repartir de 0.
                mode = "ab"
                if have > 0 and resp.status != 206:
                    mode, have = "wb", 0
                started = time.time()
                got = 0
                with open(dest, mode) as handle:
                    while True:
                        chunk = resp.read(CHUNK)
                        if not chunk:
                            break
                        handle.write(chunk)
                        got += len(chunk)
            now = os.path.getsize(dest)
            speed = got / 1e6 / max(time.time() - started, 0.01)
            print(f"[{name}] essai {attempt} : +{got / 1e6:.0f} Mo "
                  f"({now / 1e6:.0f}/{size / 1e6:.0f} Mo, {speed:.1f} Mo/s)", flush=True)
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            print(f"[{name}] essai {attempt} interrompu : {type(exc).__name__} "
                  f"{str(exc)[:80]} — reprise…", file=sys.stderr, flush=True)
            time.sleep(3)

    final = os.path.getsize(dest) if os.path.exists(dest) else 0
    if final < size:
        print(f"[ÉCHEC] {name} incomplet ({final / 1e6:.0f}/{size / 1e6:.0f} Mo) "
              f"après {MAX_ATTEMPTS} essais.", file=sys.stderr, flush=True)
        sys.exit(1)


def main() -> int:
    os.makedirs(OUT_DIR, exist_ok=True)
    for name, url in MODELS.items():
        download(name, url)
    print("[OK] Tous les GGUF sont téléchargés.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
