from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from src.other_functions import load_json, normalize_text, safe_slug
from src.routing.routing_rules import ROUTE_KEYWORDS


BASE_DIR = Path(__file__).resolve().parent.parent
RAW_FILE = BASE_DIR / "data" / "raw" / "kev" / "known_exploited_vulnerabilities.json"
OUTPUT_DIR = BASE_DIR / "data" / "optimized_chunks" / "kev"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def extract_cwes(item: dict[str, Any]) -> list[str]:
    """
    Extrae la lista de CWE desde una entrada KEV.

    Args:
        item (dict[str, Any]): Entrada individual del catálogo KEV.

    Returns:
        list[str]: Lista de CWE normalizados en minúsculas.
    """
    raw_cwes = item.get("cwes", [])

    if not isinstance(raw_cwes, list):
        return []

    return [
        str(cwe).strip().lower()
        for cwe in raw_cwes
        if str(cwe).strip()
    ]


def build_chunk_text(item: dict[str, Any]) -> str:
    """
    Construye el texto semántico del chunk a partir de una entrada KEV.

    Args:
        item (dict[str, Any]): Entrada individual del catálogo KEV.

    Returns:
        str: Texto consolidado del chunk.
    """
    cve = item.get("cveID", "unknown-cve")
    vendor = item.get("vendorProject", "")
    product = item.get("product", "")
    vuln_name = item.get("vulnerabilityName", "")
    short_desc = item.get("shortDescription", "")
    required_action = item.get("requiredAction", "")
    due_date = item.get("dueDate", "")
    ransomware = item.get("knownRansomwareCampaignUse", "")
    notes = item.get("notes", "")
    cwes = extract_cwes(item)

    parts = [
        f"CVE: {cve}",
        f"Vendor: {vendor}",
        f"Product: {product}",
        f"Vulnerability name: {vuln_name}",
        f"Description: {short_desc}",
        f"Required action: {required_action}",
        f"Due date: {due_date}",
        f"Known ransomware campaign use: {ransomware}",
        f"CWES: {', '.join(cwes)}" if cwes else "",
        f"Notes: {notes}",
        "Source: CISA Known Exploited Vulnerabilities Catalog",
    ]
    return "\n".join(part for part in parts if part and not part.endswith(": "))


def build_search_blob(item: dict[str, Any], chunk_text: str) -> str:
    """
    Construye el texto sobre el que aplicar routing.
    
    Args:
        item (dict[str, Any]): Entrada KEV original
        chunk_text (str): Texto consolidado del chunk
    
    Returns:
        str:  Texto normalizado para clasificación heurística
    """
    cwes = extract_cwes(item)
    
    parts = [
        item.get("cveID", ""),
        item.get("vendorProject", ""),
        item.get("product", ""),
        item.get("vulnerabilityName", ""),
        item.get("shortDescription", ""),
        item.get("requiredAction", ""),
        item.get("notes", ""),
        " ".join(cwes),
        chunk_text,
    ]
    return normalize_text(" ".join(str(part) for part in parts if part))


def keyword_matches(blob: str, keyword: str) -> bool:
    """
    Comprueba si una keyword aparece en el texto evitando falsos positivos

    Args:
        blob (str): Texto normalizado donde buscar
        keyword (str): Keyword a comprobar

    Returns:
        bool: True si hay coincidencia válida
    """
    normalized_keyword = normalize_text(keyword)

    if not normalized_keyword:
        return False

    if " " in normalized_keyword:
        return normalized_keyword in blob

    pattern = r"\b" + re.escape(normalized_keyword) + r"\b"
    return re.search(pattern, blob) is not None


def classify_routes(item: dict[str, Any], chunk_text: str) -> list[str]:
    """
    Devuelve las rutas temáticas a las que pertenece una entrada KEV (chunk)

    Un chunk puede pertenecer a varias rutas.
    Si no encaja en ninguna, se clasifica como 'general'

    Agrs:
        item (dict[str, Any]): Entrada KEV original
        chunk_text (str): Texto consolidado del chunk
    
    Returns:
        list[str]: Lista de rutas detectadas 
    """
    blob = build_search_blob(item, chunk_text)
    matched_routes: list[str] = []

    for route_name, keywords in ROUTE_KEYWORDS.items():
        for keyword in keywords:
            if keyword_matches(blob, keyword):
                matched_routes.append(route_name)
                break

    if not matched_routes:
        matched_routes.append("general")

    return sorted(set(matched_routes))


def build_chunk_payload(item: dict[str, Any]) -> dict[str, Any]:
    """
    Construye el JSON final del chunk optimizado
    
    Args:
        item (dict[str, Any]): Entrada KEV original

    Returns:
        dict[str, Any]: Chunk optimizado para clasificación e indexación
    """
    cve = item.get("cveID", "unknown-cve")
    cwes = extract_cwes(item)
    chunk_text = build_chunk_text(item)
    routes = classify_routes(item, chunk_text)

    return {
        "id": cve,
        "source": "kev",
        "source_type": "json_feed",
        "title": item.get("vulnerabilityName") or cve,
        "text": chunk_text,
        "metadata": {
            "cve_id": cve,
            "vendor": item.get("vendorProject"),
            "product": item.get("product"),
            "date_added": item.get("dateAdded"),
            "due_date": item.get("dueDate"),
            "ransomware_use": item.get("knownRansomwareCampaignUse"),
            "notes": item.get("notes"),
            "cwes": cwes,
            "routes": routes,
        },
    }


def preprocess_kev(raw_file: Path, output_dir: Path) -> int:
    """
    Preprocesa la fuente KEV y genera chunks optimizados en disco

    Args:
        raw_file (Path): Ruta al JSON raw de KEV
        output_dir (Path): Directorio de salida para los chunks

    Returns:
        int: Número de chunks generados
    """
    if not raw_file.exists():
        raise FileNotFoundError(f"No existe el fichero raw de KEV: {raw_file}")

    output_dir.mkdir(parents=True, exist_ok=True)

    payload = load_json(raw_file)
    vulnerabilities = payload.get("vulnerabilities", [])

    total = 0
    for item in vulnerabilities:
        chunk = build_chunk_payload(item)
        filename = f"{safe_slug(chunk['id'])}.json"
        output_path = output_dir / filename
        output_path.write_text(
            json.dumps(chunk, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        total += 1

    return total