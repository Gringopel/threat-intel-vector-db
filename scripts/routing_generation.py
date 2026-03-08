from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from src.other_functions import load_json, save_json

BASE_DIR = Path(__file__).resolve().parent.parent

CHUNKS_DIR = BASE_DIR / "data" / "optimized_chunks" / "kev"
OUTPUT_DIR = BASE_DIR / "data" / "routing"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_FILE = OUTPUT_DIR / "kev_routing_index.json"


def build_chunk_routing_entry(chunk: dict[str, Any]) -> dict[str, Any]:
    """
    Construye la representación reducida de un chunk dentro del índice de routing
    
    Args:
        chunk (dict[str, Any]): Chunk de entrada
    
    Returns:
        dict[str, Any]: Chunk reducido
    """
    metadata = chunk.get("metadata", {})
    return {
        "id": chunk.get("id"),
        "title": chunk.get("title"),
        "routes": metadata.get("routes"),
        "vendor": metadata.get("vendor"),
        "product": metadata.get("product"),
        "cve_id": metadata.get("cve_id"),
        "cwes": metadata.get("cwes"),
        "date_added": metadata.get("date_added"),
        "due_date": metadata.get("due_date"),
        "ransomware_use": metadata.get("ransomware_use"),
    }


def summarize_route(route_name: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Genera un resumen estructurado de una ruta temática.

    No usa LLM; sintetiza:
    - número de CVEs
    - vendors más frecuentes
    - productos más frecuentes
    - cwes más frecuentes
    - CVEs con uso en campañas ransomware, si existen
    """
    vendor_counter: Counter[str] = Counter()
    product_counter: Counter[str] = Counter()
    cwes_counter: Counter[str] = Counter()
    ransomware_cves: list[str] = []

    for item in items:
        vendor = item.get("vendor")
        product = item.get("product")
        cwes = item.get("cwes")
        ransomware_use = str(item.get("ransomware_use") or "").strip().lower()

        if vendor:
            vendor_counter[str(vendor)] += 1
        if product:
            product_counter[str(product)] += 1
        if cwes:
            for cwe in cwes:
                cwes_counter[str(cwe)] += 1
        if ransomware_use in {"known", "yes", "true"}:
            ransomware_cves.append(str(item.get("cve_id")))

    top_vendors = [name for name, _ in vendor_counter.most_common(5)]
    top_products = [name for name, _ in product_counter.most_common(5)]
    top_cwes = [name for name, _ in cwes_counter.most_common(5)]

    summary_text = (
        f"Route '{route_name}' contains {len(items)} KEV vulnerabilities. "
        f"Most frequent vendors: {', '.join(top_vendors) if top_vendors else 'n/a'}. "
        f"Most frequent products: {', '.join(top_products) if top_products else 'n/a'}. "
        f"Most frequent cwes: {', '.join(top_cwes) if top_cwes else 'n/a'}. "
        f"Known ransomware-related CVEs in this route: {len(ransomware_cves)}."
    )

    return {
        "route": route_name,
        "summary": summary_text,
        "document_count": len(items),
        "top_vendors": top_vendors,
        "top_products": top_products,
        "top_cwes": top_cwes,
        "ransomware_related_cves": ransomware_cves[:25],
        "cve_ids": [item["cve_id"] for item in items if item.get("cve_id")],
    }


def main() -> None:
    """Genera el índice de routing para la fuente KEV."""
    if not CHUNKS_DIR.exists():
        raise FileNotFoundError(
            f"No existe el directorio de chunks KEV: {CHUNKS_DIR}"
        )

    chunk_files = sorted(CHUNKS_DIR.glob("*.json"))
    if not chunk_files:
        raise FileNotFoundError(
            f"No se encontraron chunks JSON en: {CHUNKS_DIR}"
        )

    route_to_items: dict[str, list[dict[str, Any]]] = defaultdict(list)
    chunk_entries: list[dict[str, Any]] = []

    for chunk_file in chunk_files:
        chunk = load_json(chunk_file)
        chunk_entry = build_chunk_routing_entry(chunk)
        chunk_entries.append(chunk_entry)

        metadata = chunk.get("metadata")        
        for route in metadata.get("routes"):
            route_to_items[route].append(chunk_entry)

    route_summaries = []
    for route_name in sorted(route_to_items.keys()):
        route_summary = summarize_route(route_name, route_to_items[route_name])
        route_summaries.append(route_summary)

    payload = {
        "source": "kev",
        "routing_strategy": "heuristic_keyword_grouping",
        "routes_available": sorted(route_to_items.keys()),
        "total_chunks": len(chunk_entries),
        "route_count": len(route_summaries),
        "route_summaries": route_summaries,
        "chunks": chunk_entries,
    }

    save_json(OUTPUT_FILE, payload)

    print(f"[OK] Routing KEV generado en: {OUTPUT_FILE}")
    print(f"[INFO] total_chunks={len(chunk_entries)}")
    print(f"[INFO] route_count={len(route_summaries)}")
    print(f"[INFO] routes={', '.join(payload['routes_available'])}")


if __name__ == "__main__":
    main()