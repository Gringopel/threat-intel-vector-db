from __future__ import annotations

import json
import hashlib
import os
from urllib.request import urlopen, Request
from typing import Any
from pathlib import Path
from dotenv import load_dotenv

from src.other_functions import save_json, load_json

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
RAW_DIR = BASE_DIR / "data" / "raw"
STATE_DIR = BASE_DIR / "data" / "state"

STATE_FILE = STATE_DIR / "sources_state.json"

RAW_DIR.mkdir(parents=True, exist_ok=True)
STATE_DIR.mkdir(parents=True, exist_ok=True)


KEV_URL = os.getenv(
    "KEV_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)

MITRE_URL = os.getenv(
    "MITRE_ENTERPRISE_ATTACK_URL",
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
)

ENISA_URL = os.getenv(
    "ENISA_PDF_URL",
    "https://www.enisa.europa.eu/sites/default/files/2025-10/ENISA%20Threat%20Landscape%202025%20Booklet.pdf",
)

def sha256_bytes(data: bytes) -> str:
    """
    Calcula el hash SHA-256 de un bloque de bytes para despues determinar si hay cambios.
    
    Args:
        data (bytes): Datos en crudo para hashear
    
    Return:
        (str) hash de los datos"""
    return hashlib.sha256(data).hexdigest()


def download_bytes(url: str, timeout: int = 60) -> bytes:
    """
    Descarga el contenido de una URL y lo devuelve como bytes.

    Args:
        url (str): URL a descargar.
        timeout (int): Timeout de la petición en segundos.

    Returns:
        bytes: Contenido descargado.
    """
    request = Request(
        url,
        headers={"User-Agent": "threat-intel-vector-db/1.0"},
    )

    with urlopen(request, timeout=timeout) as response:
        return response.read()

def load_state() -> dict[str, Any]:
    if not STATE_FILE.exists():
        return {"sources": {}}
    return load_json(STATE_FILE)


def save_state(state: dict[str, Any]) -> None:
    save_json(STATE_FILE, state)


def update_source_state(state: dict[str, Any], source: str, new_hash: str, output_file: Path, records: int | None = None):

    sources = state.setdefault("sources", {})
    source_state = sources.setdefault(source, {})

    old_hash = source_state.get("sha256")
    changed = new_hash != old_hash

    source_state.update(
        {
            "source": source,
            "raw_file": str(output_file),
            "sha256": new_hash,
            "records": records,
            "exists": True,
            "changed": changed,
        }
    )

    return changed



def fetch_kev(state: dict[str, Any]) -> dict[str, Any]:
    """
    Descarga el feed KEV y devuelve su contenido parseado como dict
    
    Returns:
        dict[str, Any]: Metadatos de la descarga
    """
    output_dir = RAW_DIR / "kev"
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / "known_exploited_vulnerabilities.json"
    raw_bytes = download_bytes(KEV_URL)
    payload = json.loads(raw_bytes.decode("utf-8"))

    file_hash = sha256_bytes(raw_bytes)

    payload["_meta"] = {
        "source": "kev",
        "source_url": KEV_URL,
        "sha256": file_hash,
    }

    save_json(output_file, payload)

    changed = update_source_state(
        state,
        "kev",
        file_hash,
        output_file,
        len(payload.get("vulnerabilities", [])),
    )

    return changed


def fetch_mitre(state: dict[str, Any]) -> dict[str, Any]:
    """
    Descarga la fuente MITRE ATT&CK Enterprise y la guarda en disco

    Returns:
        dict[str, Any]: Metadatos de la descarga
    """
    output_dir = RAW_DIR / "mitre"
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / "enterprise-attack.json"
    raw_bytes = download_bytes(MITRE_URL)

    # Corrige un problema con saltos de linea
    text = raw_bytes.decode("utf-8")
    text = text.replace("\u2028", "\n").replace("\u2029", "\n")

    payload = json.loads(text)

    file_hash = sha256_bytes(raw_bytes)

    if isinstance(payload, dict):
        payload["_meta"] = {
            "source": "mitre",
            "source_url": MITRE_URL,
            "sha256": file_hash,
        }

    save_json(output_file, payload)

    changed = update_source_state(
        state,
        "mitre",
        file_hash,
        output_file,
        len(payload.get("objects", [])),
    )

    return changed


def fetch_enisa(state: dict[str, Any]) -> dict[str, Any]:
    """
    Descarga el PDF de ENISA y lo guarda en disco

    La URL se toma de ENISA_PDF_URL en .env

    Returns:
        dict[str, Any]: Metadatos de la descarga
    """
    output_dir = RAW_DIR / "enisa"
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / "enisa_threat_landscape.pdf"
    raw_bytes = download_bytes(ENISA_URL)
    file_hash = sha256_bytes(raw_bytes)
    output_file.write_bytes(raw_bytes)

    meta_file = output_dir / "enisa_threat_landscape.meta.json"

    save_json(
        meta_file,
        {
            "source": "enisa",
            "source_url": ENISA_URL,
            "sha256": file_hash,
            "filename": output_file.name,
        },
    )

    changed = update_source_state(
        state,
        "enisa",
        file_hash,
        output_file,
    )

    return changed


def main() -> None:
    state = load_state()

    print("Descargando fuentes...")

    try:
        changed = fetch_kev(state)
        print(f"[OK] KEV descargado (changed={changed})")
    except Exception as exc:
        print(f"[ERROR] Error al descargar KEV: {exc}")

    try:
        changed = fetch_mitre(state)
        print(f"[OK] MITRE descargado (changed={changed})")
    except Exception as exc:
        print(f"[ERROR] Error al descargar MITRE: {exc}")

    try:
        changed = fetch_enisa(state)
        print(f"[OK] ENISA descargado (changed={changed})")
    except Exception as exc:
        print(f"[INFO] ENISA no descargado: {exc}")

    save_state(state)

    print(f"[OK] Estado actualizado en {STATE_FILE}")


if __name__ == "__main__":
    main()
