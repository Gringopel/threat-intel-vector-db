from __future__ import annotations

import json
import os
import time
import uuid
import hashlib
from dotenv import load_dotenv
from google.genai import errors as genai_errors
from pathlib import Path
from typing import Any
from google import genai
from google.genai import types
from qdrant_client import QdrantClient
from qdrant_client.http.models import Distance, PointStruct, VectorParams

from src.other_functions import load_json

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
CHUNKS_BASE_DIR = BASE_DIR / "data" / "optimized_chunks"

PROGRESS_DIR = BASE_DIR / "data" / "state"
PROGRESS_DIR.mkdir(parents=True, exist_ok=True)
PROGRESS_FILE = PROGRESS_DIR / "index_progress.json"

DEFAULT_SLEEP_SECONDS = float(os.getenv("EMBED_SLEEP_SECONDS", "0.35"))
DEFAULT_MAX_RETRIES = int(os.getenv("EMBED_MAX_RETRIES", "6"))
DEFAULT_RETRY_BASE_SECONDS = float(os.getenv("EMBED_RETRY_BASE_SECONDS", "2.0"))

DEFAULT_QDRANT_URL = "http://localhost:6333"
DEFAULT_COLLECTION_NAME = "threat_intel"
DEFAULT_EMBEDDING_MODEL = "gemini-embedding-001"
DEFAULT_BATCH_SIZE = 64

def load_progress(path: Path) -> dict[str, Any]:
    """Carga el progreso previo de indexación si existe."""
    if not path.exists():
        return {"completed_ids": []}
    return json.loads(path.read_text(encoding="utf-8"))


def save_progress(path: Path, completed_ids: list[str]) -> None:
    """Guarda el progreso actual de indexación."""
    payload = {"completed_ids": completed_ids}
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def get_collection_point_count(
    qdrant_client: QdrantClient,
    collection_name: str,
) -> int:
    """
    Devuelve el número de puntos almacenados en una colección de Qdrant

    Args:
        qdrant_client (QdrantClient): Cliente de Qdrant
        collection_name (str): Nombre de la colección

    Returns:
        int: Número de puntos en la colección
    """
    try:
        collection_info = qdrant_client.get_collection(collection_name)
        return int(collection_info.points_count or 0)
    except Exception:
        return 0


def load_all_chunks(chunks_base_dir: Path) -> list[dict[str, Any]]:
    """
    Carga todos los chunks JSON de todas las fuentes disponibles

    Args:
        chunks_base_dir (Path): Directorio base que contiene subdirectorios por fuente

    Returns:
        list[dict[str, Any]]: Lista de chunks de todas las fuentes
    """
    if not chunks_base_dir.exists():
        raise FileNotFoundError(
            f"No existe el directorio base de chunks: {chunks_base_dir}"
        )

    chunks: list[dict[str, Any]] = []

    source_dirs = sorted(
        path for path in chunks_base_dir.iterdir()
        if path.is_dir()
    )

    if not source_dirs:
        raise FileNotFoundError(
            f"No se encontraron subdirectorios de fuentes en: {chunks_base_dir}"
        )

    for source_dir in source_dirs:
        chunk_files = sorted(source_dir.glob("*.json"))
        for path in chunk_files:
            chunks.append(load_json(path))

    if not chunks:
        raise FileNotFoundError(
            f"No se encontraron chunks JSON en ningún subdirectorio de: {chunks_base_dir}"
        )

    return chunks


def build_progress_id(chunk: dict[str, Any]) -> str:
    """Genera el ID usado para controlar el progreso de indexación."""
    return f"{chunk.get('source')}::{chunk.get('id')}"


def build_qdrant_point_id(source: str, logical_id: str) -> str:
    """Genera un UUID determinista válido para Qdrant a partir del ID lógico

    Args:
        source (str): Nombre de la fuente, por ejemplo 'kev'
        logical_id (str): ID lógico del documento, por ejemplo un CVE

    Returns:
        str: UUID en formato string.
    """
    seed = f"{source}:{logical_id}"
    return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))


def build_content_hash(chunk: dict[str, Any]) -> str:
    """
    Genera un hash determinista del contenido relevante del chunk

    Args:
        chunk (dict[str, Any]): Chunk optimizado

    Returns:
        str: Hash SHA-256 del contenido relevante
    """
    metadata = chunk.get("metadata", {})

    relevant_payload = {
        "id": chunk.get("id"),
        "source": chunk.get("source"),
        "source_type": chunk.get("source_type"),
        "title": chunk.get("title"),
        "text": chunk.get("text"),

        # COMUNES        
        "routes": metadata.get("routes", []),

        # KEV
        "cve_id": metadata.get("cve_id"),
        "vendor": metadata.get("vendor"),
        "product": metadata.get("product"),
        "date_added": metadata.get("date_added"),
        "due_date": metadata.get("due_date"),
        "ransomware_use": metadata.get("ransomware_use"),
        "notes": metadata.get("notes"),
        "cwes": metadata.get("cwes", []),

        # MITRE
        "attack_id": metadata.get("attack_id"),
        "name": metadata.get("name"),
        "description": metadata.get("description"),
        "external_url": metadata.get("external_url"),
        "tactic": metadata.get("tactic"),
        "tactics": metadata.get("tactics", []),
        "tactic_shortnames": metadata.get("tactic_shortnames", []),
        "platforms": metadata.get("platforms", []),
        "data_sources": metadata.get("data_sources", []),
        "is_subtechnique": metadata.get("is_subtechnique"),
        "parent_attack_id": metadata.get("parent_attack_id"),
        "parent_name": metadata.get("parent_name"),
        "permissions_required": metadata.get("permissions_required", []),
        "defense_bypassed": metadata.get("defense_bypassed", []),
        "effective_permissions": metadata.get("effective_permissions", []),
        "detection": metadata.get("detection"),
        "mitigations": metadata.get("mitigations", []),
        "software": metadata.get("software", []),
        "groups": metadata.get("groups", []),

        # ENISA
        "section_id": metadata.get("section_id"),
        "parent_section_id": metadata.get("parent_section_id"),
        "root_section_id": metadata.get("root_section_id"),
        "root_section": metadata.get("root_section"),
        "parent_title": metadata.get("parent_title"),
        "hierarchical_title": metadata.get("hierarchical_title"),
        "page_start": metadata.get("page_start"),
        "page_end": metadata.get("page_end"),
        "logical_page": metadata.get("logical_page"),
        "level": metadata.get("level"),
        "is_leaf": metadata.get("is_leaf"),
        "document_type": metadata.get("document_type"),
        "report_year": metadata.get("report_year"),
    }

    raw = json.dumps(relevant_payload, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def build_embedding_input_enisa(chunk: dict[str, Any]) -> str:
    metadata = chunk.get("metadata", {})
    routes = metadata.get("routes", [])

    parts = [
        "Source: ENISA",
        f"Title: {chunk.get('title', '')}",
        f"Section ID: {metadata.get('section_id', '')}",
        f"Hierarchy: {metadata.get('hierarchical_title', '')}",
        f"Root section: {metadata.get('root_section', '')}",
        f"Parent title: {metadata.get('parent_title', '')}",
        f"Level: {metadata.get('level', '')}",
        f"Is leaf: {metadata.get('is_leaf', '')}",
        f"Document type: {metadata.get('document_type', '')}",
        f"Report year: {metadata.get('report_year', '')}",
        f"Routes: {', '.join(routes) if routes else ''}",
        f"Text: {chunk.get('text', '')}",
    ]
    return "\n".join(
        part for part in parts
        if part.split(": ", 1)[-1].strip()
    )


def build_embedding_input_mitre(chunk: dict[str, Any]) -> str:
    metadata = chunk.get("metadata", {})
    routes = metadata.get("routes", [])
    tactics = metadata.get("tactics", [])
    tactic_shortnames = metadata.get("tactic_shortnames", [])
    platforms = metadata.get("platforms", [])
    data_sources = metadata.get("data_sources", [])
    permissions_required = metadata.get("permissions_required", [])
    defense_bypassed = metadata.get("defense_bypassed", [])
    effective_permissions = metadata.get("effective_permissions", [])

    mitigations = metadata.get("mitigations", [])
    software = metadata.get("software", [])
    groups = metadata.get("groups", [])

    mitigation_names = [
        item.get("name", "")
        for item in mitigations
        if isinstance(item, dict) and item.get("name")
    ]
    software_names = [
        item.get("name", "")
        for item in software
        if isinstance(item, dict) and item.get("name")
    ]
    group_names = [
        item.get("name", "")
        for item in groups
        if isinstance(item, dict) and item.get("name")
    ]

    parts = [
        "Source: MITRE ATT&CK",
        f"Title: {chunk.get('title', '')}",
        f"Source type: {chunk.get('source_type', '')}",
        f"ID: {chunk.get('id', '')}",
        f"ATT&CK ID: {metadata.get('attack_id', '')}",
        f"Tactic: {metadata.get('tactic', '')}",
        f"Tactics: {', '.join(tactics) if tactics else ''}",
        f"Tactic shortnames: {', '.join(tactic_shortnames) if tactic_shortnames else ''}",
        f"Platforms: {', '.join(platforms) if platforms else ''}",
        f"Data sources: {', '.join(data_sources) if data_sources else ''}",
        f"Parent ATT&CK ID: {metadata.get('parent_attack_id', '')}",
        f"Parent technique: {metadata.get('parent_name', '')}",
        f"Permissions required: {', '.join(permissions_required) if permissions_required else ''}",
        f"Defense bypassed: {', '.join(defense_bypassed) if defense_bypassed else ''}",
        f"Effective permissions: {', '.join(effective_permissions) if effective_permissions else ''}",
        f"Mitigations: {', '.join(mitigation_names) if mitigation_names else ''}",
        f"Software: {', '.join(software_names) if software_names else ''}",
        f"Groups: {', '.join(group_names) if group_names else ''}",
        f"Routes: {', '.join(routes) if routes else ''}",
        f"Text: {chunk.get('text', '')}",
    ]
    return "\n".join(
        part for part in parts
        if part.split(": ", 1)[-1].strip()
    )


def build_embedding_input_kev(chunk: dict[str, Any]) -> str:
    metadata = chunk.get("metadata", {})
    routes = metadata.get("routes", [])
    cwes = metadata.get("cwes", [])

    parts = [
        "Source: CISA KEV",
        f"Title: {chunk.get('title', '')}",
        f"Source type: {chunk.get('source_type', '')}",
        f"ID: {chunk.get('id', '')}",
        f"CVE: {metadata.get('cve_id', '')}",
        f"Vendor: {metadata.get('vendor', '')}",
        f"Product: {metadata.get('product', '')}",
        f"CWEs: {', '.join(cwes) if cwes else ''}",
        f"Date added: {metadata.get('date_added', '')}",
        f"Due date: {metadata.get('due_date', '')}",
        f"Ransomware use: {metadata.get('ransomware_use', '')}",
        f"Notes: {metadata.get('notes', '')}",
        f"Routes: {', '.join(routes) if routes else ''}",
        f"Text: {chunk.get('text', '')}",
    ]
    return "\n".join(
        part for part in parts
        if part.split(": ", 1)[-1].strip()
    )


def build_embedding_input(chunk: dict[str, Any]) -> str:
    """
    Construye el texto que se enviará al modelo de embeddings.

    Args:
        chunk (dict[str, Any]): Chunk optimizado.

    Returns:
        str: Texto enriquecido para embedding.
    """

    source = str(chunk.get("source", "")).lower()

    if source == "enisa":
        return build_embedding_input_enisa(chunk)
    if source == "mitre":
        return build_embedding_input_mitre(chunk)
    if source == "kev":
        return build_embedding_input_kev(chunk)
    

    metadata = chunk.get("metadata", {})
    
    parts = [
        f"Title: {chunk.get('title', '')}",
        f"Source: {chunk.get('source', '')}",
        f"Source type: {chunk.get('source_type', '')}",
        f"Routes: {', '.join(metadata.get('routes', []))}",
        f"Text: {chunk.get('text', '')}",
    ]
    return "\n".join(part for part in parts if part.split(": ", 1)[-1].strip())


def generate_embedding(
    client: genai.Client,
    text: str,
    model: str,
    max_retries: int = DEFAULT_MAX_RETRIES,
    retry_base_seconds: float = DEFAULT_RETRY_BASE_SECONDS,
) -> list[float]:
    """
    Genera un embedding con reintentos y backoff exponencial por si surgen errores
    
    Args:
        client (genai.Client): Cliente de Google GenAI
        text (str): Texto que se va a 
        model (str): Texto de entrada que se enviará al modelo para generar el embedding
        model (str): Nombre del modelo de embeddings que se utilizará
        max_entries (int): Número máximo de reintentos en caso de error del servicio
        retry_base_seconds (float): Tiempo base en segundos utilizado para calcular el backoff exponencial
        entre reintentos
    
    Returns:
        list[float]: Vector embedding generado por el modelo
        
    Raises:
        RuntimeError: Si no se puede generar el embedding tras agotar todos los reintentos
        ValueError: Si la respuesta del modelo no contiene embeddings válidos
    """
    last_error: Exception | None = None

    for attempt in range(1, max_retries + 1):
        try:
            config = types.EmbedContentConfig(
                task_type="RETRIEVAL_DOCUMENT",
            )

            result = client.models.embed_content(
                model=model,
                contents=text,
                config=config,
            )

            if not result.embeddings:
                raise ValueError("El modelo devolvió una respuesta sin embeddings.")

            values = result.embeddings[0].values
            if not values:
                raise ValueError("El embedding devuelto está vacío.")

            return list(values)

        except genai_errors.ServerError as exc:
            last_error = exc
            wait_seconds = retry_base_seconds * (2 ** (attempt - 1))
            print(
                f"[WARN] ServerError en embedding (intento {attempt}/{max_retries}). "
                f"Esperando {wait_seconds:.1f}s..."
            )
            time.sleep(wait_seconds)

        except Exception as exc:
            last_error = exc
            break

    raise RuntimeError(f"No se pudo generar el embedding tras varios intentos: {last_error}")


def ensure_collection(
    qdrant_client: QdrantClient,
    collection_name: str,
    vector_size: int,
) -> None:
    """
    Crea la colección Qdrant si no existe

    Args:
        qdrant_client (QdrantClient): Cliente de Qdrant
        collection_name (str): Nombre de la colección
        vector_size (int): Dimensión del embedding

    Returns:
        None
    """
    collections = qdrant_client.get_collections().collections
    existing_names = {collection.name for collection in collections}

    if collection_name in existing_names:
        print(f"[INFO] La colección ya existe: {collection_name}")
        return

    qdrant_client.create_collection(
        collection_name=collection_name,
        vectors_config=VectorParams(
            size=vector_size,
            distance=Distance.COSINE,
        ),
    )
    print(f"[OK] Colección creada: {collection_name}")


def get_existing_payload(
    qdrant_client: QdrantClient,
    collection_name: str,
    source: str,
    logical_id: str,
) -> dict[str, Any] | None:
    """
    Recupera el payload de un punto existente en Qdrant a partir de su ID determinista

    Args:
        qdrant_client (QdrantClient): Cliente de Qdrant
        collection_name (str): Nombre de la colección
        source (str): Fuente del documento
        logical_id (str): ID lógico del documento

    Returns:
        dict[str, Any] | None: Payload existente o None si no existe
    """
    point_id = build_qdrant_point_id(source=source, logical_id=logical_id)

    try:
        response = qdrant_client.retrieve(
            collection_name=collection_name,
            ids=[point_id],
            with_payload=True,
            with_vectors=False,
        )
        if response:
            return response[0].payload or {}
        return None
    except Exception:
        return None


def should_skip_chunk(
    qdrant_client: QdrantClient,
    collection_name: str,
    chunk: dict[str, Any],
) -> bool:
    """
    Determina si un chunk puede saltarse porque ya existe en Qdrant
    y su contenido no ha cambiado

    Args:
        qdrant_client (QdrantClient): Cliente de Qdrant
        collection_name (str): Nombre de la colección
        chunk (dict[str, Any]): Chunk optimizado

    Returns:
        bool: True si no hace falta reindexarlo
    """
    source = str(chunk.get("source", "unknown"))
    logical_id = str(chunk.get("id"))
    current_hash = build_content_hash(chunk)

    existing_payload = get_existing_payload(
        qdrant_client=qdrant_client,
        collection_name=collection_name,
        source=source,
        logical_id=logical_id,
    )

    if not existing_payload:
        return False

    stored_hash = existing_payload.get("content_hash")
    return stored_hash == current_hash


def build_point(chunk: dict[str, Any], embedding: list[float]) -> PointStruct:
    """Construye un PointStruct para insertar en Qdrant.

    Args:
        chunk (dict[str, Any]): Chunk optimizado.
        embedding (list[float]): Vector embedding del chunk.

    Returns:
        PointStruct: Punto listo para upsert en Qdrant.
    """
    metadata = chunk.get("metadata", {})
    logical_id = str(chunk.get("id"))
    source = str(chunk.get("source", "unknown"))
    content_hash = build_content_hash(chunk)

    payload = {
        "id": logical_id,
        "title": chunk.get("title"),
        "text": chunk.get("text"),
        "source": source,
        "source_type": chunk.get("source_type"),
        "content_hash": content_hash,
        "routes": metadata.get("routes", []),

        # KEV
        "cve_id": metadata.get("cve_id"),
        "vendor": metadata.get("vendor"),
        "product": metadata.get("product"),
        "date_added": metadata.get("date_added"),
        "due_date": metadata.get("due_date"),
        "ransomware_use": metadata.get("ransomware_use"),
        "notes": metadata.get("notes"),
        "cwes": metadata.get("cwes"),
        
        # MITRE
        "attack_id": metadata.get("attack_id"),
        "name": metadata.get("name"),
        "description": metadata.get("description"),
        "external_url": metadata.get("external_url"),
        "tactic": metadata.get("tactic"),
        "tactics": metadata.get("tactics", []),
        "tactic_shortnames": metadata.get("tactic_shortnames", []),
        "platforms": metadata.get("platforms", []),
        "data_sources": metadata.get("data_sources", []),
        "is_subtechnique": metadata.get("is_subtechnique"),
        "parent_attack_id": metadata.get("parent_attack_id"),
        "parent_name": metadata.get("parent_name"),
        "permissions_required": metadata.get("permissions_required", []),
        "defense_bypassed": metadata.get("defense_bypassed", []),
        "effective_permissions": metadata.get("effective_permissions", []),
        "detection": metadata.get("detection"),
        "mitigations": metadata.get("mitigations", []),
        "software": metadata.get("software", []),
        "groups": metadata.get("groups", []),

        # ENISA
        "section_id": metadata.get("section_id"),
        "parent_section_id": metadata.get("parent_section_id"),
        "root_section_id": metadata.get("root_section_id"),
        "root_section": metadata.get("root_section"),
        "parent_title": metadata.get("parent_title"),
        "hierarchical_title": metadata.get("hierarchical_title"),
        "page_start": metadata.get("page_start"),
        "page_end": metadata.get("page_end"),
        "logical_page": metadata.get("logical_page"),
        "level": metadata.get("level"),
        "is_leaf": metadata.get("is_leaf"),
        "document_type": metadata.get("document_type"),
        "report_year": metadata.get("report_year"),        
    }

    point_id = build_qdrant_point_id(source=source, logical_id=logical_id)

    return PointStruct(
        id=point_id,
        vector=embedding,
        payload=payload,
    )


def main() -> None:
    google_api_key = os.environ.get("GOOGLE_API_KEY")
    qdrant_url = os.environ.get("QDRANT_URL", DEFAULT_QDRANT_URL)
    collection_name = os.environ.get("QDRANT_COLLECTION", DEFAULT_COLLECTION_NAME)
    embedding_model = os.environ.get("EMBEDDING_MODEL", DEFAULT_EMBEDDING_MODEL)
    batch_size = int(os.environ.get("INDEX_BATCH_SIZE", str(DEFAULT_BATCH_SIZE)))
    sleep_seconds = float(os.environ.get("EMBED_SLEEP_SECONDS", str(DEFAULT_SLEEP_SECONDS)))

    if not google_api_key:
        raise EnvironmentError(
            "No se encontró GOOGLE_API_KEY. Añádela al entorno o al fichero .env."
        )

    chunks = load_all_chunks(CHUNKS_BASE_DIR)
    print(f"[INFO] Chunks cargados: {len(chunks)}")
    print(f"[INFO] EMBEDDING_MODEL={embedding_model}")
    print(f"[INFO] EMBED_SLEEP_SECONDS={sleep_seconds}")
    print(f"[INFO] INDEX_BATCH_SIZE={batch_size}")

    genai_client = genai.Client(api_key=google_api_key)
    qdrant_client = QdrantClient(url=qdrant_url)

    existing_names = {
        collection.name
        for collection in qdrant_client.get_collections().collections
    }

    collection_exists = collection_name in existing_names
    qdrant_count = get_collection_point_count(qdrant_client, collection_name) if collection_exists else 0
    print(f"[INFO] Puntos actuales en Qdrant: {qdrant_count}")

    progress = load_progress(PROGRESS_FILE)
    completed_ids = set(progress.get("completed_ids", []))

    if len(completed_ids) > 0 and qdrant_count == 0:
        print("[WARN] El progreso local indica documentos procesados, pero la colección está vacía.")
        print("[WARN] Se ignorará el progreso y se reindexará todo.")
        completed_ids = set()

    pending_chunks: list[dict[str, Any]] = []
    skipped_unchanged = 0

    for chunk in chunks:
        progress_id = build_progress_id(chunk)

        if progress_id not in completed_ids:
            pending_chunks.append(chunk)
            continue

        if qdrant_count == 0:
            pending_chunks.append(chunk)
            continue

        if should_skip_chunk(
            qdrant_client=qdrant_client,
            collection_name=collection_name,
            chunk=chunk,
        ):
            skipped_unchanged += 1
            continue

        pending_chunks.append(chunk)

    print(f"[INFO] Chunks pendientes: {len(pending_chunks)}")
    print(f"[INFO] Chunks sin cambios omitidos: {skipped_unchanged}")

    if not pending_chunks:
        print("[OK] No hay chunks pendientes de indexar.")
        return

    first_text = build_embedding_input(pending_chunks[0])
    first_embedding = generate_embedding(
        client=genai_client,
        text=first_text,
        model=embedding_model,
    )
    vector_size = len(first_embedding)

    ensure_collection(qdrant_client, collection_name, vector_size)

    current_batch: list[PointStruct] = []
    current_batch_ids: list[str] = []
    completed_ids_list = list(completed_ids)

    for index, chunk in enumerate(pending_chunks, start=1):
        text = build_embedding_input(chunk)
        logical_progress_id = build_progress_id(chunk)

        embedding = (first_embedding if index == 1 else generate_embedding(
            client=genai_client,
            text=text,
            model=embedding_model,)
        )

        current_batch.append(build_point(chunk, embedding))
        completed_ids_list.append(logical_progress_id)

        if len(current_batch) >= batch_size:
            qdrant_client.upsert(
                collection_name=collection_name,
                points=current_batch,
                wait=True,
            )
            completed_ids_list.extend(current_batch_ids)
            completed_ids_list = sorted(set(completed_ids_list))

            save_progress(PROGRESS_FILE, completed_ids_list)
            print(f"[INFO] Upsert batch completado. Total procesados: {len(completed_ids_list)}")

            current_batch = []
            current_batch_ids = []

        if index % 25 == 0:
            print(f"[INFO] Embeddings generados: {index}/{len(pending_chunks)}")

        time.sleep(sleep_seconds)

    if current_batch:
        qdrant_client.upsert(
            collection_name=collection_name,
            points=current_batch,
            wait=True,
        )
        completed_ids_list.extend(current_batch_ids)
        completed_ids_list = sorted(set(completed_ids_list))
        save_progress(PROGRESS_FILE, completed_ids_list)

    print(f"[OK] Indexación finalizada en colección: {collection_name}")
    print(f"[OK] Total indexados acumulados: {len(completed_ids_list)}")
    print(f"[OK] Progreso guardado en: {PROGRESS_FILE}")

if __name__ == "__main__":
    main()