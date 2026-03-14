from __future__ import annotations

import asyncio
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from dotenv import load_dotenv
from tenacity import retry, stop_after_attempt, wait_fixed
from langchain_google_genai import ChatGoogleGenerativeAI

from src.other_functions import load_json, save_json

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

CHUNKS_ROOT_DIR = BASE_DIR / "data" / "optimized_chunks"
OUTPUT_DIR = BASE_DIR / "data" / "routing"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_FILE = OUTPUT_DIR / "kev_routing_index.json"

STATE_FILE = BASE_DIR / "data" / "state" / "sources_state.json"

SOURCE_DIRS: dict[str, Path] = {
    "kev": CHUNKS_ROOT_DIR / "kev",
    "mitre": CHUNKS_ROOT_DIR / "mitre",
    "enisa": CHUNKS_ROOT_DIR / "enisa",
}

llm_langchain = ChatGoogleGenerativeAI(
    model="gemini-2.5-flash-lite",
    temperature=0,
    max_retries=3
)

MAX_REPRESENTATIVE_CHUNKS = 8
MAX_TEXT_PER_CHUNK = 1200


def load_chunks_from_dir(chunks_dir: Path) -> list[dict[str, Any]]:
    """
    Carga todos los chunks JSON de un directorio.

    Args:
        chunks_dir (Path): Directorio de entrada.

    Returns:
        list[dict[str, Any]]: Lista de chunks.
    """
    if not chunks_dir.exists():
        raise FileNotFoundError(f"No existe el directorio de chunks: {chunks_dir}")

    chunk_files = sorted(chunks_dir.glob("*.json"))
    if not chunk_files:
        raise FileNotFoundError(f"No se encontraron chunks JSON en: {chunks_dir}")

    return [load_json(path) for path in chunk_files]


def safe_list(value: Any) -> list[Any]:
    """Devuelve una lista segura para valores que pueden venir como None o escalar"""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def trim_text(text: str, limit: int = MAX_TEXT_PER_CHUNK) -> str:
    """
    Recorta un texto largo para usarlo en prompts de resumen

    Args:
        text (str): Texto original
        limit (int): Número máximo de caracteres

    Returns:
        str: Texto recortado.
    """
    clean = (text or "").strip()
    if len(clean) <= limit:
        return clean
    return clean[:limit].rstrip() + "..."


def build_group_document_text(source: str, route_name: str, items: list[dict[str, Any]]) -> str:
    """
    Construye un texto representativo del grupo para resumir con LLM

    Args:
        source (str): Fuente
        route_name (str): Ruta temática
        items (list[dict[str, Any]]): Items reducidos del grupo

    Returns:
        str: Texto consolidado representativo.
    """
    header = [
        f"Source: {source}",
        f"Route: {route_name}",
        f"Document count: {len(items)}",
        "",
        "Representative chunks:",
    ]

    parts: list[str] = ["\n".join(header)]

    for item in items[:MAX_REPRESENTATIVE_CHUNKS]:
        fragment_lines = [
            f"Title: {item.get('title', '')}",
            f"Routes: {', '.join(safe_list(item.get('routes')))}",
        ]

        if source == "enisa":
            fragment_lines.extend([
                f"Hierarchy: {item.get('hierarchical_title', '')}",
                f"Root section: {item.get('root_section', '')}",
                f"Section ID: {item.get('section_id', '')}",
            ])
        elif source == "mitre":
            fragment_lines.extend([
                f"ATT&CK ID: {item.get('attack_id', '')}",
                f"Tactic: {item.get('tactic', '')}",
                f"Tactics: {', '.join(safe_list(item.get('tactics')))}",
                f"Platforms: {', '.join(safe_list(item.get('platforms')))}",
                f"Groups: {', '.join(safe_list(item.get('groups')))}",
                f"Software: {', '.join(safe_list(item.get('software')))}",
            ])
        elif source == "kev":
            fragment_lines.extend([
                f"CVE: {item.get('cve_id', '')}",
                f"Vendor: {item.get('vendor', '')}",
                f"Product: {item.get('product', '')}",
                f"CWEs: {', '.join(safe_list(item.get('cwes')))}",
                f"Ransomware use: {item.get('ransomware_use', '')}",
            ])

        fragment_lines.append(f"Text: {trim_text(item.get('text', ''))}")
        parts.append("\n".join(line for line in fragment_lines if line.split(": ", 1)[-1].strip()))

    return "\n\n".join(parts)


def top_values(counter: Counter[str], limit: int = 5) -> list[str]:
    """Extrae las claves más frecuentes de un Counter."""
    return [name for name, _ in counter.most_common(limit)]


@retry(wait=wait_fixed(5), stop=stop_after_attempt(3))
async def summarize_with_llm(prompt_text: str) -> str:
    """
    Genera un resumen usando el LLM del proyecto

    Args:
        prompt_text (str): Prompt final

    Returns:
        str: Resumen del LLM
    """

    response = await llm_langchain.ainvoke(prompt_text)
    content = getattr(response, "content", response)
    return str(content).strip()


def build_route_prompt(document_text: str) -> str:
    """Construye el prompt de resumen por ruta."""
    return f"""Eres un asistente experto en threat intelligence y routing semántico.
Tu objetivo es crear un resumen corto y general que ayude a decidir si una consulta
de usuario debería buscar en esta ruta temática.

Devuelve entre 2 y 4 frases en inglés, claras y generales.
No enumeres todos los elementos ni repitas títulos completos innecesariamente.
No inventes información que no aparezca en el texto.

Texto del grupo:
{document_text}

Resumen:"""


async def enrich_route_summaries_with_llm(
    source: str,
    route_summaries: list[dict[str, Any]],
    route_to_items: dict[str, list[dict[str, Any]]],
) -> None:
    """
    Enriquece los resúmenes por ruta con una versión generada por LLM

    Args:
        source (str): Fuente
        route_summaries (list[dict[str, Any]]): Resúmenes estructurados
        route_to_items (dict[str, list[dict[str, Any]]]): Chunks agrupados por ruta

    Returns:
        None
    """
    for route_summary in route_summaries:
        route_name = route_summary["route"]
        items = route_to_items.get(route_name, [])
        document_text = build_group_document_text(source=source, route_name=route_name, items=items)
        llm_summary = await summarize_with_llm(build_route_prompt(document_text))
        route_summary["summary_llm"] = llm_summary or route_summary["summary_structured"]


def build_enisa_chunk_routing_entry(chunk: dict[str, Any]) -> dict[str, Any]:
    """
    Construye la representación reducida de un chunk ENISA

    Args:
        chunk (dict[str, Any]): Chunk original

    Returns:
        dict[str, Any]: Entrada reducida para routing
    """
    metadata = chunk.get("metadata", {})
    return {
        "id": chunk.get("id"),
        "title": chunk.get("title"),
        "text": chunk.get("text", ""),
        "routes": metadata.get("routes", []),
        "section_id": metadata.get("section_id"),
        "parent_section_id": metadata.get("parent_section_id"),
        "root_section_id": metadata.get("root_section_id"),
        "root_section": metadata.get("root_section"),
        "parent_title": metadata.get("parent_title"),
        "hierarchical_title": metadata.get("hierarchical_title"),
        "level": metadata.get("level"),
        "is_leaf": metadata.get("is_leaf"),
        "page_start": metadata.get("page_start"),
        "page_end": metadata.get("page_end"),
        "document_type": metadata.get("document_type"),
        "report_year": metadata.get("report_year"),
    }


def build_mitre_chunk_routing_entry(chunk: dict[str, Any]) -> dict[str, Any]:
    """
    Construye la representación reducida de un chunk MITRE

    Args:
        chunk (dict[str, Any]): Chunk original

    Returns:
        dict[str, Any]: Entrada reducida para routing
    """
    metadata = chunk.get("metadata", {})

    group_names = [
        item.get("name")
        for item in safe_list(metadata.get("groups"))
        if isinstance(item, dict) and item.get("name")
    ]
    software_names = [
        item.get("name")
        for item in safe_list(metadata.get("software"))
        if isinstance(item, dict) and item.get("name")
    ]

    return {
        "id": chunk.get("id"),
        "title": chunk.get("title"),
        "text": chunk.get("text", ""),
        "routes": metadata.get("routes", []),
        "attack_id": metadata.get("attack_id"),
        "tactic": metadata.get("tactic"),
        "tactics": metadata.get("tactics", []),
        "tactic_shortnames": metadata.get("tactic_shortnames", []),
        "platforms": metadata.get("platforms", []),
        "parent_attack_id": metadata.get("parent_attack_id"),
        "parent_name": metadata.get("parent_name"),
        "groups": group_names,
        "software": software_names,
    }


def build_kev_chunk_routing_entry(chunk: dict[str, Any]) -> dict[str, Any]:
    """
    Construye la representación reducida de un chunk KEV

    Args:
        chunk (dict[str, Any]): Chunk original

    Returns:
        dict[str, Any]: Entrada reducida para routing
    """
    metadata = chunk.get("metadata", {})
    return {
        "id": chunk.get("id"),
        "title": chunk.get("title"),
        "text": chunk.get("text", ""),
        "routes": metadata.get("routes", []),
        "vendor": metadata.get("vendor"),
        "product": metadata.get("product"),
        "cve_id": metadata.get("cve_id"),
        "cwes": metadata.get("cwes", []),
        "date_added": metadata.get("date_added"),
        "due_date": metadata.get("due_date"),
        "ransomware_use": metadata.get("ransomware_use"),
        "notes": metadata.get("notes"),
    }


def build_chunk_routing_entry(source: str, chunk: dict[str, Any]) -> dict[str, Any]:
    """
    Despacha la construcción de entradas reducidas según la fuente

    Args:
        source (str): Nombre de la fuente
        chunk (dict[str, Any]): Chunk original

    Returns:
        dict[str, Any]: Entrada reducida.
    """
    if source == "enisa":
        return build_enisa_chunk_routing_entry(chunk)
    if source == "mitre":
        return build_mitre_chunk_routing_entry(chunk)
    if source == "kev":
        return build_kev_chunk_routing_entry(chunk)

    raise ValueError(f"Fuente no soportada para routing: {source}")


def summarize_enisa_route(route_name: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Genera un resumen estructurado de una ruta ENISA

    Args:
        route_name (str): Nombre de la ruta
        items (list[dict[str, Any]]): Chunks reducidos

    Returns:
        dict[str, Any]: Resumen estructurado
    """
    root_counter: Counter[str] = Counter()
    level_counter: Counter[str] = Counter()
    leaf_count = 0

    for item in items:
        root_section = item.get("root_section")
        if root_section:
            root_counter[str(root_section)] += 1

        level = item.get("level")
        if level is not None:
            level_counter[str(level)] += 1

        if item.get("is_leaf") is True:
            leaf_count += 1

    top_root_sections = top_values(root_counter)
    top_levels = top_values(level_counter)

    summary_text = (
        f"Route '{route_name}' contains {len(items)} ENISA sections. "
        f"Most frequent root sections: {', '.join(top_root_sections) if top_root_sections else 'n/a'}. "
        f"Levels observed: {', '.join(top_levels) if top_levels else 'n/a'}. "
        f"Leaf sections in this route: {leaf_count}."
    )

    return {
        "route": route_name,
        "summary_structured": summary_text,
        "document_count": len(items),
        "top_root_sections": top_root_sections,
        "section_ids": [item["section_id"] for item in items if item.get("section_id")][:100],
        "hierarchical_titles": [
            item["hierarchical_title"]
            for item in items
            if item.get("hierarchical_title")
        ][:50],
        "leaf_count": leaf_count,
    }


def summarize_mitre_route(route_name: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Genera un resumen estructurado de una ruta MITRE

    Args:
        route_name (str): Nombre de la ruta
        items (list[dict[str, Any]]): Chunks reducidos

    Returns:
        dict[str, Any]: Resumen estructurado
    """
    tactic_counter: Counter[str] = Counter()
    platform_counter: Counter[str] = Counter()
    group_counter: Counter[str] = Counter()
    software_counter: Counter[str] = Counter()

    for item in items:
        tactic = item.get("tactic")
        if tactic:
            tactic_counter[str(tactic)] += 1

        for platform in safe_list(item.get("platforms")):
            platform_counter[str(platform)] += 1

        for group in safe_list(item.get("groups")):
            group_counter[str(group)] += 1

        for software in safe_list(item.get("software")):
            software_counter[str(software)] += 1

    top_tactics = top_values(tactic_counter)
    top_platforms = top_values(platform_counter)
    top_groups = top_values(group_counter)
    top_software = top_values(software_counter)

    summary_text = (
        f"Route '{route_name}' contains {len(items)} MITRE chunks. "
        f"Most frequent tactics: {', '.join(top_tactics) if top_tactics else 'n/a'}. "
        f"Most frequent platforms: {', '.join(top_platforms) if top_platforms else 'n/a'}. "
        f"Most frequent groups: {', '.join(top_groups) if top_groups else 'n/a'}."
    )

    return {
        "route": route_name,
        "summary_structured": summary_text,
        "document_count": len(items),
        "top_tactics": top_tactics,
        "top_platforms": top_platforms,
        "top_groups": top_groups,
        "top_software": top_software,
        "attack_ids": [item["attack_id"] for item in items if item.get("attack_id")][:100],
    }


def summarize_kev_route(route_name: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Genera un resumen estructurado de una ruta KEV

    Args:
        route_name (str): Nombre de la ruta
        items (list[dict[str, Any]]): Chunks reducidos

    Returns:
        dict[str, Any]: Resumen estructurado
    """
    vendor_counter: Counter[str] = Counter()
    product_counter: Counter[str] = Counter()
    cwes_counter: Counter[str] = Counter()
    ransomware_cves: list[str] = []

    for item in items:
        vendor = item.get("vendor")
        product = item.get("product")
        cwes = safe_list(item.get("cwes"))
        ransomware_use = str(item.get("ransomware_use") or "").strip().lower()

        if vendor:
            vendor_counter[str(vendor)] += 1
        if product:
            product_counter[str(product)] += 1
        for cwe in cwes:
            cwes_counter[str(cwe)] += 1
        if ransomware_use in {"known", "yes", "true"}:
            cve_id = item.get("cve_id")
            if cve_id:
                ransomware_cves.append(str(cve_id))

    top_vendors = top_values(vendor_counter)
    top_products = top_values(product_counter)
    top_cwes = top_values(cwes_counter)

    summary_text = (
        f"Route '{route_name}' contains {len(items)} KEV vulnerabilities. "
        f"Most frequent vendors: {', '.join(top_vendors) if top_vendors else 'n/a'}. "
        f"Most frequent products: {', '.join(top_products) if top_products else 'n/a'}. "
        f"Most frequent cwes: {', '.join(top_cwes) if top_cwes else 'n/a'}. "
        f"Known ransomware-related CVEs in this route: {len(ransomware_cves)}."
    )

    return {
        "route": route_name,
        "summary_structured": summary_text,
        "document_count": len(items),
        "top_vendors": top_vendors,
        "top_products": top_products,
        "top_cwes": top_cwes,
        "ransomware_related_cves": ransomware_cves[:25],
        "cve_ids": [item["cve_id"] for item in items if item.get("cve_id")][:100],
    }


def summarize_route(source: str, route_name: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Despacha el resumen estructurado según la fuente

    Args:
        source (str): Fuente
        route_name (str): Ruta temática
        items (list[dict[str, Any]]): Chunks reducidos del grupo

    Returns:
        dict[str, Any]: Resumen estructurado.
    """
    if source == "enisa":
        return summarize_enisa_route(route_name, items)
    if source == "mitre":
        return summarize_mitre_route(route_name, items)
    if source == "kev":
        return summarize_kev_route(route_name, items)

    raise ValueError(f"Fuente no soportada para resumen: {source}")


def build_source_structured_summary(source: str, route_summaries: list[dict[str, Any]], total_chunks: int) -> str:
    """
    Construye un resumen global determinista por fuente

    Args:
        source (str): Fuente
        route_summaries (list[dict[str, Any]]): Resúmenes por ruta
        total_chunks (int): Número total de chunks

    Returns:
        str: Resumen estructurado
    """
    route_names = [item["route"] for item in route_summaries[:12]]

    return (
        f"Source '{source}' contains {total_chunks} chunks grouped into "
        f"{len(route_summaries)} routes. Available routes include: "
        f"{', '.join(route_names) if route_names else 'n/a'}."
    )


def build_global_document_text(source_payloads: list[dict[str, Any]]) -> str:
    """
    Construye el texto de entrada para el resumen global de fuentes

    Args:
        source_payloads (list[dict[str, Any]]): Índices por fuente ya generados

    Returns:
        str: Texto consolidado
    """
    blocks: list[str] = []

    for payload in source_payloads:
        lines = [
            f"Source: {payload.get('source', '')}",
            f"Total chunks: {payload.get('total_chunks', 0)}",
            f"Available routes: {', '.join(payload.get('routes_available', []))}",
            "Route summaries:",
        ]
        for route in payload.get("route_summaries", [])[:12]:
            lines.append(
                f"- {route.get('route', '')}: "
                f"{route.get('summary_structured', route.get('summary', ''))}"
            )
        blocks.append("\n".join(lines))

    return "\n\n".join(blocks)


def build_global_prompt(document_text: str) -> str:
    """Construye el prompt de resumen global
    
    Args:
        document_text (str): Texto original para resumir
    
    Returns:
        str: Resumen
    """
    return f"""Eres un asistente experto en arquitectura RAG y threat intelligence.
Resume de forma breve el tipo de conocimiento que aporta cada fuente para ayudar a un router
a decidir dónde buscar primero.

Devuelve un resumen corto en inglés, claro y operativo.
No inventes información.

Contenido:
{document_text}

Resumen:"""


async def build_source_payload(source: str, chunks_dir: Path) -> dict[str, Any]:
    """
    Genera el índice de routing de una fuente concreta

    Args:
        source (str): Nombre de la fuente
        chunks_dir (Path): Directorio de chunks

    Returns:
        dict[str, Any]: Payload completo del índice de routing
    """
    chunks = load_chunks_from_dir(chunks_dir)

    route_to_items: dict[str, list[dict[str, Any]]] = defaultdict(list)
    chunk_entries: list[dict[str, Any]] = []

    for chunk in chunks:
        chunk_entry = build_chunk_routing_entry(source, chunk)
        chunk_entries.append(chunk_entry)

        metadata = chunk.get("metadata", {})
        routes = safe_list(metadata.get("routes"))

        if not routes:
            routes = ["general"]
            chunk_entry["routes"] = routes

        for route in routes:
            route_to_items[str(route)].append(chunk_entry)

    route_summaries: list[dict[str, Any]] = []
    for route_name in sorted(route_to_items.keys()):
        route_summary = summarize_route(source, route_name, route_to_items[route_name])
        route_summaries.append(route_summary)

    await enrich_route_summaries_with_llm(
        source=source,
        route_summaries=route_summaries,
        route_to_items=route_to_items,
    )

    structured_summary = build_source_structured_summary(
        source=source,
        route_summaries=route_summaries,
        total_chunks=len(chunk_entries),
    )

    source_payload = {
        "source": source,
        "routing_strategy": "structured_routes_plus_llm_summaries",
        "routes_available": sorted(route_to_items.keys()),
        "total_chunks": len(chunk_entries),
        "route_count": len(route_summaries),
        "summary_structured": structured_summary,
        "summary_llm": "",
        "route_summaries": route_summaries,
        "chunks": chunk_entries,
    }

    source_payload["summary_llm"] = (
        await summarize_with_llm(
            build_global_prompt(
                build_global_document_text([source_payload])
            )
        )
    ) or structured_summary

    return source_payload


async def build_global_payload(source_payloads: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Genera el índice global de routing

    Args:
        source_payloads (list[dict[str, Any]]): Índices ya generados por fuente

    Returns:
        dict[str, Any]: Índice global
    """
    global_summary_structured = (
        f"Global routing index with {len(source_payloads)} sources: "
        f"{', '.join(payload['source'] for payload in source_payloads)}."
    )

    global_summary_llm = (
        await summarize_with_llm(
            build_global_prompt(build_global_document_text(source_payloads))
        )
    ) or global_summary_structured

    return {
        "routing_strategy": "source_then_route",
        "source_count": len(source_payloads),
        "sources_available": [payload["source"] for payload in source_payloads],
        "summary_structured": global_summary_structured,
        "summary_llm": global_summary_llm,
        "sources": [
            {
                "source": payload["source"],
                "total_chunks": payload["total_chunks"],
                "route_count": payload["route_count"],
                "routes_available": payload["routes_available"],
                "summary_structured": payload["summary_structured"],
                "summary_llm": payload["summary_llm"],
            }
            for payload in source_payloads
        ],
    }


async def main() -> None:
    """Genera indices por fuente de forma incremental"""
    state = load_json(STATE_FILE)
    sources_state = state.get("sources", {})

    source_payloads: list[dict[str, Any]] = []

    for source, chunks_dir in SOURCE_DIRS.items():
        source_state = sources_state.get(source, {})
        changed = source_state.get("changed", True)
        output_file = OUTPUT_DIR / f"{source}_routing_index.json"

        should_generate = changed or not output_file.exists()
        if not should_generate:
            print(f"[INFO] {source.upper()} sin cambios. Se reutiliza routing existente.")
            payload = load_json(output_file)
            source_payloads.append(payload)
            continue

        print(f"\n[INFO] Generando routing para fuente: {source}")
        payload = await build_source_payload(source=source, chunks_dir=chunks_dir)
        
        save_json(output_file, payload)
        source_payloads.append(payload)

        print(f"[OK] Routing generado en: {output_file}")
        print(f"[INFO] total_chunks={payload['total_chunks']}")
        print(f"[INFO] route_count={payload['route_count']}")
        print(f"[INFO] routes={', '.join(payload['routes_available'])}")

    global_payload = await build_global_payload(source_payloads)
    global_output = OUTPUT_DIR / "global_routing_index.json"
    save_json(global_output, global_payload)

    print(f"\n[OK] Routing global generado en: {global_output}")
    print(f"[INFO] sources={', '.join(global_payload['sources_available'])}")


if __name__ == "__main__":
    asyncio.run(main())
