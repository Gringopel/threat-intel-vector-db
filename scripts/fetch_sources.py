from __future__ import annotations

import json
import hashlib
from urllib.request import urlopen, Request
from pathlib import Path
from src.other_functions import save_json

BASE_DIR = Path(__file__).resolve().parent.parent
RAW_DIR = BASE_DIR / "data" / "raw" / "kev"
RAW_DIR.mkdir(parents=True, exist_ok=True)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OUTPUT_FILE = RAW_DIR / "known_exploited_vulnerabilities.json"

def sha256_bytes(data: bytes) -> str:
    """
    Calcula el hash SHA-256 de un bloque de bytes para despues determinar si hay cambios.
    
    Args:
        data (bytes): Datos en crudo para hashear
    
    Return:
        (str) hash de los datos"""
    return hashlib.sha256(data).hexdigest()

def fetch_kev() -> dict:
    """Descarga el feed KEV y devuelve su contenido parseado como dict."""
    request = Request(
        KEV_URL,
        headers={
            "User-Agent": "threat-intel-rag/1.0"
        },
    )

    with urlopen(request, timeout=30) as response:
        raw_bytes = response.read()

    payload = json.loads(raw_bytes.decode("utf-8"))
    payload["_meta"] = {
        "source_url": KEV_URL,
        "sha256": sha256_bytes(raw_bytes),
    }
    return payload


def main() -> None:
    payload = fetch_kev()
    save_json(OUTPUT_FILE, payload)
    print(f"[OK] KEV descargado en: {OUTPUT_FILE}")
    print(f"[OK] Hash: {payload['_meta']['sha256']}")


if __name__ == "__main__":
    main()
