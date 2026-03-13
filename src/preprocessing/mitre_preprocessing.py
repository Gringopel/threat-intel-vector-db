from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from src.other_functions import safe_slug, load_json, normalize_text, clear_output_directory
from src.routing.routing_rules import ROUTE_KEYWORDS


def clean_text(value: str | None) -> str:
    """
    Limpia y normaliza texto libre

    Args:
        value (str | None): Texto de entrada

    Returns:
        str: Texto limpio
    """
    if not value:
        return ""
    text = str(value)
    text = re.sub(r"\(Citation:[^)]+\)", "", text)
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = re.sub(r"\s+", " ", text)
    return text.strip()


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


def normalize_string_list(values: Any) -> list[str]:
    """
    Normaliza una lista de strings

    Args:
        values (Any): Valor de entrada

    Returns:
        list[str]: Lista de strings limpios y sin duplicados
    """
    if not isinstance(values, list):
        return []

    normalized = [clean_text(str(value)) for value in values if clean_text(str(value))]
    return sorted(set(normalized))


def extract_attack_id(item: dict[str, Any]) -> str | None:
    """
    Extrae el ATT&CK ID desde external_references

    Args:
        item (dict[str, Any]): Objeto STIX

    Returns:
        str | None: ATT&CK ID o None si no existe
    """
    references = item.get("external_references", [])
    if not isinstance(references, list):
        return None

    for ref in references:
        if not isinstance(ref, dict):
            continue

        source_name = str(ref.get("source_name", "")).lower()
        external_id = ref.get("external_id")

        if source_name == "mitre-attack" and external_id:
            return clean_text(str(external_id))

    return None


def extract_external_url(item: dict[str, Any]) -> str | None:
    """
    Extrae una URL externa representativa del objeto STIX

    Args:
        item (dict[str, Any]): Objeto STIX

    Returns:
        str | None: URL encontrada o None
    """
    references = item.get("external_references", [])
    if not isinstance(references, list):
        return None

    for ref in references:
        if not isinstance(ref, dict):
            continue

        url = ref.get("url")
        if url:
            return clean_text(str(url))

    return None


def extract_platforms(item: dict[str, Any]) -> list[str]:
    """
    Extrae plataformas de una técnica ATT&CK

    Args:
        item (dict[str, Any]): Objeto STIX attack-pattern

    Returns:
        list[str]: Lista de plataformas normalizadas
    """
    platforms = item.get("x_mitre_platforms", [])
    if not isinstance(platforms, list):
        return []

    return sorted({clean_text(str(platform)).lower() for platform in platforms if clean_text(str(platform))})


def extract_data_sources(item: dict[str, Any]) -> list[str]:
    """
    Extrae data sources de una técnica ATT&CK

    Args:
        item (dict[str, Any]): Objeto STIX attack-pattern

    Returns:
        list[str]: Lista de data sources
    """
    return normalize_string_list(item.get("x_mitre_data_sources", []))


def extract_permissions_required(item: dict[str, Any]) -> list[str]:
    """
    Extrae permisos requeridos de una técnica ATT&CK

    Args:
        item (dict[str, Any]): Objeto STIX attack-pattern

    Returns:
        list[str]: Lista de permisos
    """
    return normalize_string_list(item.get("x_mitre_permissions_required", []))


def extract_defense_bypassed(item: dict[str, Any]) -> list[str]:
    """
    Extrae defensas evadidas por una técnica ATT&CK

    Args:
        item (dict[str, Any]): Objeto STIX attack-pattern

    Returns:
        list[str]: Lista de defensas evadidas
    """
    return normalize_string_list(item.get("x_mitre_defense_bypassed", []))


def extract_effective_permissions(item: dict[str, Any]) -> list[str]:
    """
    Extrae effective permissions de una técnica ATT&CK

    Args:
        item (dict[str, Any]): Objeto STIX attack-pattern

    Returns:
        list[str]: Lista de permisos efectivos
    """
    return normalize_string_list(item.get("x_mitre_effective_permissions", []))


def build_object_index(objects: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """
    Construye un índice por STIX ID

    Args:
        objects (list[dict[str, Any]]): Lista de objetos STIX

    Returns:
        dict[str, dict[str, Any]]: Índice por ID
    """
    indexed: dict[str, dict[str, Any]] = {}

    for obj in objects:
        if not isinstance(obj, dict):
            continue

        stix_id = obj.get("id")
        if stix_id:
            indexed[str(stix_id)] = obj

    return indexed


def build_relationship_index(objects: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """
    Construye un índice de relaciones por target_ref

    Args:
        objects (list[dict[str, Any]]): Lista de objetos STIX

    Returns:
        dict[str, list[dict[str, Any]]]: Relaciones agrupadas por target_ref
    """
    indexed: dict[str, list[dict[str, Any]]] = {}

    for obj in objects:
        if not isinstance(obj, dict):
            continue

        if obj.get("type") != "relationship":
            continue

        target_ref = obj.get("target_ref")
        if not target_ref:
            continue

        indexed.setdefault(str(target_ref), []).append(obj)

    return indexed


def build_tactic_name_map(objects: list[dict[str, Any]]) -> dict[str, str]:
    """
    Construye un mapa de shortname de táctica -> nombre visible

    Args:
        objects (list[dict[str, Any]]): Lista de objetos STIX

    Returns:
        dict[str, str]: Mapa shortname -> nombre
    """
    tactic_map: dict[str, str] = {}

    for obj in objects:
        if not isinstance(obj, dict):
            continue

        if obj.get("type") != "x-mitre-tactic":
            continue

        shortname = clean_text(obj.get("x_mitre_shortname"))
        name = clean_text(obj.get("name"))

        if shortname and name:
            tactic_map[shortname] = name

    return tactic_map


def extract_tactic_shortnames(item: dict[str, Any]) -> list[str]:
    """
    Extrae los shortnames de táctica desde kill_chain_phases

    Args:
        item (dict[str, Any]): Técnica ATT&CK

    Returns:
        list[str]: Lista de shortnames de táctica
    """
    phases = item.get("kill_chain_phases", [])
    if not isinstance(phases, list):
        return []

    shortnames: list[str] = []

    for phase in phases:
        if not isinstance(phase, dict):
            continue

        kill_chain_name = clean_text(phase.get("kill_chain_name")).lower()
        phase_name = clean_text(phase.get("phase_name")).lower()

        if kill_chain_name == "mitre-attack" and phase_name:
            shortnames.append(phase_name)

    return sorted(set(shortnames))


def extract_tactics(item: dict[str, Any], tactic_name_map: dict[str, str]) -> list[str]:
    """
    Extrae nombres de táctica legibles

    Args:
        item (dict[str, Any]): Técnica ATT&CK
        tactic_name_map (dict[str, str]): Mapa shortname -> nombre

    Returns:
        list[str]: Lista de tácticas legibles.
    """
    shortnames = extract_tactic_shortnames(item)
    tactics = [tactic_name_map.get(shortname, shortname) for shortname in shortnames]
    return sorted(set(tactics))


def extract_parent_technique(
    item: dict[str, Any],
    object_index: dict[str, dict[str, Any]],
) -> dict[str, str | None]:
    """
    Extrae la técnica padre si el objeto es una sub-técnica

    Args:
        item (dict[str, Any]): Técnica ATT&CK
        object_index (dict[str, dict[str, Any]]): Índice de objetos STIX por ID

    Returns:
        dict[str, str | None]: attack_id y nombre de la técnica padre.
    """
    stix_id = str(item.get("id", ""))
    if not stix_id:
        return {"parent_attack_id": None, "parent_name": None}

    for rel_obj in object_index.values():
        if rel_obj.get("type") != "relationship":
            continue

        if rel_obj.get("relationship_type") != "subtechnique-of":
            continue

        if str(rel_obj.get("source_ref", "")) != stix_id:
            continue

        parent_ref = str(rel_obj.get("target_ref", ""))
        parent_obj = object_index.get(parent_ref)
        if not parent_obj:
            continue

        return {
            "parent_attack_id": extract_attack_id(parent_obj),
            "parent_name": clean_text(parent_obj.get("name")),
        }
    return {"parent_attack_id": None, "parent_name": None}

def extract_related_entities(
    item: dict[str, Any],
    object_index: dict[str, dict[str, Any]],
) -> dict[str, list[dict[str, str]]]:
    """
    Extrae mitigaciones, software y grupos relacionados con una técnica

    Args:
        item (dict[str, Any]): Técnica ATT&CK
        object_index (dict[str, dict[str, Any]]): Índice de objetos STIX

    Returns:
        dict[str, list[dict[str, str]]]: Entidades relacionadas
    """
    stix_id = str(item.get("id", ""))
    mitigations: list[dict[str, str]] = []
    software: list[dict[str, str]] = []
    groups: list[dict[str, str]] = []

    for obj in object_index.values():
        if obj.get("type") != "relationship":
            continue

        relationship_type = str(obj.get("relationship_type", ""))
        source_ref = str(obj.get("source_ref", ""))
        target_ref = str(obj.get("target_ref", ""))

        if target_ref != stix_id:
            continue

        source_obj = object_index.get(source_ref)
        if not source_obj:
            continue

        source_type = str(source_obj.get("type", ""))
        source_name = clean_text(source_obj.get("name"))
        source_attack_id = extract_attack_id(source_obj) or ""

        if relationship_type == "mitigates" and source_type == "course-of-action":
            mitigations.append(
                {
                    "id": source_attack_id,
                    "name": source_name,
                }
            )

        elif relationship_type == "uses" and source_type in {"tool", "malware"}:
            software.append(
                {
                    "id": source_attack_id,
                    "name": source_name,
                    "type": source_type,
                }
            )

        elif relationship_type == "uses" and source_type == "intrusion-set":
            groups.append(
                {
                    "id": source_attack_id,
                    "name": source_name,
                }
            )

    return {
        "mitigations": sorted(
            mitigations,
            key=lambda item: (item.get("id", ""), item.get("name", "")),
        ),
        "software": sorted(
            software,
            key=lambda item: (item.get("id", ""), item.get("name", "")),
        ),
        "groups": sorted(
            groups,
            key=lambda item: (item.get("id", ""), item.get("name", "")),
        ),
    }


def map_platforms_to_routes(platforms: list[str]) -> list[str]:
    """
    Mapea plataformas ATT&CK a rutas temáticas del proyecto

    Args:
        platforms (list[str]): Plataformas ATT&CK

    Returns:
        list[str]: Rutas detectadas
    """
    routes: list[str] = []

    for platform in platforms:
        if platform in {"windows"}:
            routes.append("windows")
        elif platform in {"linux", "macos"}:
            routes.append("linux_unix")
        elif platform in {"containers"}:
            routes.append("virtualization_cloud")
        elif platform in {"network"}:
            routes.append("network_edge_devices")
        elif platform in {
            "office suite",
            "saas",
            "iaas",
            "google workspace",
            "azure ad",
        }:
            routes.append("identity_access")
        elif platform in {"android", "ios"}:
            routes.append("mobile")

    return sorted(set(routes))


def map_tactics_to_routes(tactic_shortnames: list[str]) -> list[str]:
    """
    Mapea tácticas ATT&CK a rutas temáticas cuando aporta contexto útil

    Args:
        tactic_shortnames (list[str]): Shortnames de táctica

    Returns:
        list[str]: Rutas detectadas
    """
    routes: list[str] = []

    for tactic in tactic_shortnames:
        if tactic in {"initial-access"}:
            routes.append("network_edge_devices")
        elif tactic in {"credential-access"}:
            routes.append("identity_access")
        elif tactic in {"command-and-control"}:
            routes.append("network_edge_devices")
        elif tactic in {"collection", "exfiltration"}:
            routes.append("security_tools")

    return sorted(set(routes))


def build_chunk_text(
    item: dict[str, Any],
    tactic_name_map: dict[str, str],
    object_index: dict[str, dict[str, Any]],
) -> str:
    """
    Construye el texto semántico del chunk a partir de una técnica ATT&CK

    Args:
        item (dict[str, Any]): Técnica ATT&CK en formato STIX
        tactic_name_map (dict[str, str]): Mapa shortname -> nombre
        object_index (dict[str, dict[str, Any]]): Índice STIX por ID

    Returns:
        str: Texto consolidado del chunk
    """
    attack_id = extract_attack_id(item) or "unknown-technique"
    name = clean_text(item.get("name"))
    description = clean_text(item.get("description"))
    platforms = extract_platforms(item)
    data_sources = extract_data_sources(item)
    permissions = extract_permissions_required(item)
    defense_bypassed = extract_defense_bypassed(item)
    effective_permissions = extract_effective_permissions(item)
    detection = clean_text(item.get("x_mitre_detection"))
    system_requirements = normalize_string_list(item.get("x_mitre_system_requirements", []))
    tactic_shortnames = extract_tactic_shortnames(item)
    tactics = extract_tactics(item, tactic_name_map)
    is_subtechnique = bool(item.get("x_mitre_is_subtechnique", False))
    parent_info = extract_parent_technique(item, object_index)
    related_entities = extract_related_entities(item, object_index)

    mitigation_names = [m.get("name", "") for m in related_entities["mitigations"] if m.get("name")]
    software_names = [s.get("name", "") for s in related_entities["software"] if s.get("name")]
    group_names = [g.get("name", "") for g in related_entities["groups"] if g.get("name")]

    parts = [
        f"ATT&CK ID: {attack_id}",
        f"Technique name: {name}",
        f"Description: {description}",
        f"Tactics: {', '.join(tactics)}" if tactics else "",
        f"Tactic shortnames: {', '.join(tactic_shortnames)}" if tactic_shortnames else "",
        f"Platforms: {', '.join(platforms)}" if platforms else "",
        f"Data sources: {', '.join(data_sources)}" if data_sources else "",
        f"Permissions required: {', '.join(permissions)}" if permissions else "",
        f"Effective permissions: {', '.join(effective_permissions)}" if effective_permissions else "",
        f"Defense bypassed: {', '.join(defense_bypassed)}" if defense_bypassed else "",
        f"System requirements: {', '.join(system_requirements)}" if system_requirements else "",
        f"Detection: {detection}" if detection else "",
        f"Is sub-technique: {is_subtechnique}",
        (
            f"Parent technique: {parent_info['parent_attack_id']} - {parent_info['parent_name']}"
            if parent_info["parent_attack_id"] or parent_info["parent_name"]
            else ""
        ),
        f"Mitigations: {', '.join(mitigation_names)}" if mitigation_names else "",
        f"Associated software: {', '.join(software_names)}" if software_names else "",
        f"Associated groups: {', '.join(group_names)}" if group_names else "",
        "Source: MITRE ATT&CK Enterprise",
    ]

    return "\n".join(part for part in parts if part and not part.endswith(": "))


def build_search_blob(
    item: dict[str, Any],
    chunk_text: str,
    tactic_name_map: dict[str, str],
    object_index: dict[str, dict[str, Any]],
) -> str:
    """
    Construye el texto sobre el que aplicar clasificación heurística

    Args:
        item (dict[str, Any]): Técnica ATT&CK original
        chunk_text (str): Texto consolidado del chunk
        tactic_name_map (dict[str, str]): Mapa shortname -> nombre
        object_index (dict[str, dict[str, Any]]): Índice STIX por ID

    Returns:
        str: Texto normalizado para clasificación
    """
    platforms = extract_platforms(item)
    data_sources = extract_data_sources(item)
    tactic_shortnames = extract_tactic_shortnames(item)
    tactics = extract_tactics(item, tactic_name_map)
    parent_info = extract_parent_technique(item, object_index)
    related_entities = extract_related_entities(item, object_index)

    related_names = []
    related_names.extend(m.get("name", "") for m in related_entities["mitigations"])
    related_names.extend(s.get("name", "") for s in related_entities["software"])
    related_names.extend(g.get("name", "") for g in related_entities["groups"])

    parts = [
        extract_attack_id(item) or "",
        clean_text(item.get("name")),
        clean_text(item.get("description")),
        " ".join(platforms),
        " ".join(data_sources),
        " ".join(tactic_shortnames),
        " ".join(tactics),
        clean_text(item.get("x_mitre_detection")),
        parent_info.get("parent_attack_id") or "",
        parent_info.get("parent_name") or "",
        " ".join(name for name in related_names if name),
        chunk_text,
    ]
    return normalize_text(" ".join(str(part) for part in parts if part))


def classify_routes(
    item: dict[str, Any],
    chunk_text: str,
    tactic_name_map: dict[str, str],
    object_index: dict[str, dict[str, Any]],
) -> list[str]:
    """
    Clasifica una técnica ATT&CK en una o varias rutas temáticas

    Args:
        item (dict[str, Any]): Técnica ATT&CK original
        chunk_text (str): Texto consolidado del chunk
        tactic_name_map (dict[str, str]): Mapa shortname -> nombre
        object_index (dict[str, dict[str, Any]]): Índice STIX por ID

    Returns:
        list[str]: Lista de rutas detectadas.
    """
    blob = build_search_blob(
        item=item,
        chunk_text=chunk_text,
        tactic_name_map=tactic_name_map,
        object_index=object_index,
    )

    matched_routes = []
    matched_routes.extend(map_platforms_to_routes(extract_platforms(item)))
    matched_routes.extend(map_tactics_to_routes(extract_tactic_shortnames(item)))

    for route_name, keywords in ROUTE_KEYWORDS.items():
        for keyword in keywords:
            if keyword_matches(blob, keyword):
                matched_routes.append(route_name)
                break

    if not matched_routes:
        matched_routes.append("general")

    return sorted(set(matched_routes))


def is_valid_attack_pattern(item: dict[str, Any]) -> bool:
    """
    Determina si un objeto STIX es una técnica ATT&CK válida para indexación

    Args:
        item (dict[str, Any]): Objeto STIX

    Returns:
        bool: True si debe indexarse
    """
    if item.get("type") != "attack-pattern":
        return False

    if item.get("revoked") is True:
        return False

    if item.get("x_mitre_deprecated") is True:
        return False

    return extract_attack_id(item) is not None


def build_chunk_payload(
    item: dict[str, Any],
    tactic_name_map: dict[str, str],
    object_index: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """
    Construye el JSON final del chunk optimizado para MITRE ATT&CK

    Args:
        item (dict[str, Any]): Técnica ATT&CK original
        tactic_name_map (dict[str, str]): Mapa shortname -> nombre
        object_index (dict[str, dict[str, Any]]): Índice STIX por ID

    Returns:
        dict[str, Any]: Chunk optimizado.
    """
    attack_id = extract_attack_id(item) or "unknown-technique"
    chunk_text = build_chunk_text(
        item=item,
        tactic_name_map=tactic_name_map,
        object_index=object_index,
    )
    routes = classify_routes(
        item=item,
        chunk_text=chunk_text,
        tactic_name_map=tactic_name_map,
        object_index=object_index,
    )
    platforms = extract_platforms(item)
    data_sources = extract_data_sources(item)
    tactic_shortnames = extract_tactic_shortnames(item)
    tactics = extract_tactics(item, tactic_name_map)
    parent_info = extract_parent_technique(item, object_index)
    related_entities = extract_related_entities(item, object_index)

    return {
        "id": attack_id,
        "source": "mitre",
        "source_type": "stix_2_1_json",
        "title": clean_text(item.get("name")) or attack_id,
        "text": chunk_text,
        "metadata": {
            "attack_id": attack_id,
            "name": clean_text(item.get("name")),
            "description": clean_text(item.get("description")),
            "external_url": extract_external_url(item),
            "platforms": platforms,
            "data_sources": data_sources,
            "tactic": tactics[0] if tactics else None,
            "tactics": tactics,
            "tactic_shortnames": tactic_shortnames,
            "is_subtechnique": bool(item.get("x_mitre_is_subtechnique", False)),
            "parent_attack_id": parent_info.get("parent_attack_id"),
            "parent_name": parent_info.get("parent_name"),
            "permissions_required": extract_permissions_required(item),
            "defense_bypassed": extract_defense_bypassed(item),
            "effective_permissions": extract_effective_permissions(item),
            "detection": clean_text(item.get("x_mitre_detection")),
            "mitigations": related_entities["mitigations"],
            "software": related_entities["software"],
            "groups": related_entities["groups"],
            "routes": routes,
        },
    }


def preprocess_mitre(raw_file: Path, output_dir: Path) -> int:
    """
    Preprocesa la fuente MITRE ATT&CK Enterprise y genera chunks optimizados

    Args:
        raw_file (Path): Ruta al JSON raw de MITRE
        output_dir (Path): Directorio de salida para los chunks

    Returns:
        int: Número de chunks generados.
    """
    if not raw_file.exists():
        raise FileNotFoundError(f"No existe el fichero raw de MITRE: {raw_file}")

    payload = load_json(raw_file)
    objects = payload.get("objects", [])

    if not isinstance(objects, list):
        raise ValueError("El fichero MITRE no contiene una lista válida en 'objects'.")

    clear_output_directory(output_dir)

    object_index = build_object_index(objects)
    tactic_name_map = build_tactic_name_map(objects)

    total = 0
    for item in objects:
        if not isinstance(item, dict):
            continue

        if not is_valid_attack_pattern(item):
            continue

        chunk = build_chunk_payload(
            item=item,
            tactic_name_map=tactic_name_map,
            object_index=object_index,
        )

        filename = f"{safe_slug(chunk['id'])}.json"
        output_path = output_dir / filename
        output_path.write_text(
            json.dumps(chunk, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        total += 1

    return total
