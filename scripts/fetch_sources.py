from __future__ import annotations

import json
import hashlib
import os
from urllib.request import urlopen, Request
from typing import Any
from pathlib import Path
from dotenv import load_dotenv

from src.other_functions import save_json

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
RAW_DIR = BASE_DIR / "data" / "raw"
STATE_DIR = BASE_DIR / "data" / "state"

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


def save_binary_file(path: Path, data: bytes) -> None:
    """
    Guarda un fichero binario en disco.

    Args:
        path (Path): Ruta de salida.
        data (bytes): Contenido a guardar.

    Returns:
        None
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def fetch_kev() -> dict[str, Any]:
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

    payload["_meta"] = {
        "source": "kev",
        "source_url": KEV_URL,
        "sha256": sha256_bytes(raw_bytes),
    }

    save_json(output_file, payload)

    return {
        "source": "kev",
        "output_file": str(output_file),
        "sha256": payload["_meta"]["sha256"],
        "records": len(payload.get("vulnerabilities", [])),
    }


def fetch_mitre() -> dict[str, Any]:
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

    if isinstance(payload, dict):
        payload["_meta"] = {
            "source": "mitre",
            "source_url": MITRE_URL,
            "sha256": sha256_bytes(raw_bytes),
        }

    save_json(output_file, payload)

    return {
        "source": "mitre",
        "output_file": str(output_file),
        "sha256": sha256_bytes(raw_bytes),
        "objects": len(payload.get("objects", [])) if isinstance(payload, dict) else None,
    }


def fetch_enisa() -> dict[str, Any]:
    """
    Descarga el PDF de ENISA y lo guarda en disco

    La URL se toma de ENISA_PDF_URL en .env

    Returns:
        dict[str, Any]: Metadatos de la descarga
    """
    if not ENISA_URL:
        raise EnvironmentError(
            "No se encontró ENISA_PDF_URL en el entorno o en .env."
        )

    output_dir = RAW_DIR / "enisa"
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / "enisa_threat_landscape.pdf"
    raw_bytes = download_bytes(ENISA_URL)
    file_hash = sha256_bytes(raw_bytes)

    save_binary_file(output_file, raw_bytes)

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

    return {
        "source": "enisa",
        "output_file": str(output_file),
        "sha256": file_hash,
        "meta_file": str(meta_file),
    }


def main() -> None:
    results: list[dict[str, Any]] = []

    try:
        kev_result = fetch_kev()
        results.append(kev_result)
        print(
            f"[OK] KEV descargado: {kev_result['output_file']} "
            f"(records={kev_result['records']})"
        )
    except Exception as exc:
        print(f"[ERROR] Error al descargar KEV: {exc}")

    try:
        mitre_result = fetch_mitre()
        results.append(mitre_result)
        print(
            f"[OK] MITRE descargado: {mitre_result['output_file']} "
            f"(objects={mitre_result['objects']})"
        )
    except Exception as exc:
        print(f"[ERROR] Error al descargar MITRE: {exc}")

    try:
        enisa_result = fetch_enisa()
        results.append(enisa_result)
        print(f"[OK] ENISA descargado: {enisa_result['output_file']}")
    except Exception as exc:
        print(f"[INFO] ENISA no descargado: {exc}")

    summary_file = STATE_DIR / "fetch_sources_summary.json"
    save_json(summary_file, {"results": results})
    print(f"[OK] Resumen de descarga guardado en: {summary_file}")


if __name__ == "__main__":
    main()
