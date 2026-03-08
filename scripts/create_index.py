from __future__ import annotations

import json
import os
import time
import uuid
from dotenv import load_dotenv
from google.genai import errors as genai_errors
from pathlib import Path
from typing import Any, Iterable
from google import genai
from google.genai import types
from qdrant_client import QdrantClient
from qdrant_client.http.models import Distance, PointStruct, VectorParams

from src.other_functions import load_json

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
CHUNKS_DIR = BASE_DIR / "data" / "optimized_chunks" / "kev"

PROGRESS_DIR = BASE_DIR / "data" / "state"
PROGRESS_DIR.mkdir(parents=True, exist_ok=True)
PROGRESS_FILE = PROGRESS_DIR / "kev_index_progress.json"

DEFAULT_SLEEP_SECONDS = float(os.getenv("EMBED_SLEEP_SECONDS", "0.35"))
DEFAULT_MAX_RETRIES = int(os.getenv("EMBED_MAX_RETRIES", "6"))
DEFAULT_RETRY_BASE_SECONDS = float(os.getenv("EMBED_RETRY_BASE_SECONDS", "2.0"))

DEFAULT_QDRANT_URL = "http://localhost:6333"
DEFAULT_COLLECTION_NAME = "threat_intel_kev"
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


# def load_env_file(env_path: Path) -> None:
#     """Carga variables simples KEY=VALUE desde un .env si existe.

#     Args:
#         env_path: Ruta al archivo .env.

#     Returns:
#         None.
#     """
#     if not env_path.exists():
#         return

#     for line in env_path.read_text(encoding="utf-8").splitlines():
#         line = line.strip()

#         if not line or line.startswith("#") or "=" not in line:
#             continue

#         key, value = line.split("=", 1)
#         key = key.strip()
#         value = value.strip().strip('"').strip("'")

#         if key and key not in os.environ:
#             os.environ[key] = value


def load_chunks(chunks_dir: Path) -> list[dict[str, Any]]:
    """Carga todos los chunks JSON de un directorio

    Args:
        chunks_dir (Path): Directorio que contiene chunks

    Returns:
        list[dict[str, Any]]: Lista de chunks
    """
    if not chunks_dir.exists():
        raise FileNotFoundError(f"No existe el directorio de chunks: {chunks_dir}")

    chunk_files = sorted(chunks_dir.glob("*.json"))
    if not chunk_files:
        raise FileNotFoundError(f"No se encontraron chunks en: {chunks_dir}")

    return [load_json(path) for path in chunk_files]


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


def build_embedding_input(chunk: dict[str, Any]) -> str:
    """
    Construye el texto que se enviará al modelo de embeddings.

    Args:
        chunk (dict[str, Any]): Chunk optimizado.

    Returns:
        str: Texto enriquecido para embedding.
    """
    metadata = chunk.get("metadata", {})
    routes = metadata.get("routes", [])
    cwes = metadata.get("cwes", [])

    parts = [
        f"Title: {chunk.get('title', '')}",
        f"Source: {chunk.get('source', '')}",
        f"CVE: {metadata.get('cve_id', '')}",
        f"Vendor: {metadata.get('vendor', '')}",
        f"Product: {metadata.get('product', '')}"
        f"Routes: {', '.join(routes) if routes else ''}",
        F"CWEs: {', '.join(cwes) if cwes else ''}",
        f"Text: {chunk.get('text', '')}",
    ]
    return "\n".join(part for part in parts if part.strip())


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

    payload = {
        "id": logical_id,
        "title": chunk.get("title"),
        "text": chunk.get("text"),
        "source": source,
        "source_type": chunk.get("source_type"),
        "cve_id": metadata.get("cve_id"),
        "vendor": metadata.get("vendor"),
        "product": metadata.get("product"),
        "date_added": metadata.get("date_added"),
        "due_date": metadata.get("due_date"),
        "ransomware_use": metadata.get("ransomware_use"),
        "notes": metadata.get("notes"),
        "cwes": metadata.get("cwes"),
        "routes": metadata.get("routes", []),
    }

    point_id = build_qdrant_point_id(source=source, logical_id=logical_id)

    return PointStruct(
        id=point_id,
        vector=embedding,
        payload=payload,
    )


def batched(items: list[Any], batch_size: int) -> Iterable[list[Any]]:
    """
    Divide una lista en lotes

    Args:
        items (list[Any]): Lista de elementos
        batch_size (int): Tamaño del lote

    Yields:
        Iterable[list[Any]]: Sublistas de tamaño batch_size
    """
    for index in range(0, len(items), batch_size):
        yield items[index:index + batch_size]


def get_collection_point_count(
    qdrant_client: QdrantClient,
    collection_name: str,
) -> int:
    """
    Devuelve el número de puntos almacenados en una colección de Qdrant.

    Args:
        qdrant_client (QdrantClient): Cliente de Qdrant.
        collection_name (str): Nombre de la colección.

    Returns:
        int: Número de puntos en la colección.
    """
    try:
        collection_info = qdrant_client.get_collection(collection_name)
        return int(collection_info.points_count or 0)
    except Exception:
        return 0


def main() -> None:
    #load_env_file(BASE_DIR / ".env")

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

    chunks = load_chunks(CHUNKS_DIR)
    print(f"[INFO] Chunks cargados: {len(chunks)}")
    print(f"[INFO] EMBEDDING_MODEL={embedding_model}")
    print(f"[INFO] EMBED_SLEEP_SECONDS={sleep_seconds}")
    print(f"[INFO] INDEX_BATCH_SIZE={batch_size}")

    genai_client = genai.Client(api_key=google_api_key)
    qdrant_client = QdrantClient(url=qdrant_url)

    collection_exists = False
    existing_names = {
        collection.name
        for collection in qdrant_client.get_collections().collections
    }
    if collection_name in existing_names:
        collection_exists = True

    progress = load_progress(PROGRESS_FILE)
    completed_ids = set(progress.get("completed_ids", []))

    qdrant_count = get_collection_point_count(qdrant_client, collection_name) if collection_exists else 0

    print(f"[INFO] Progress IDs: {len(completed_ids)}")
    print(f"[INFO] Qdrant points: {qdrant_count}")

    if len(completed_ids) > 0 and qdrant_count == 0:
        print("[WARN] El progreso local indica documentos procesados, pero la colección está vacía.")
        print("[WARN] Se ignorará el progreso y se reindexará todo.")
        completed_ids = set()

    pending_chunks = [chunk for chunk in chunks if str(chunk.get("id")) not in completed_ids]
    print(f"[INFO] Chunks pendientes: {len(pending_chunks)}")

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
        embedding = first_embedding if index == 1 else generate_embedding(
            client=genai_client,
            text=text,
            model=embedding_model,
        )

        current_batch.append(build_point(chunk, embedding))
        completed_ids_list.append(str(chunk.get("id")))

        if len(current_batch) >= batch_size:
            qdrant_client.upsert(
                collection_name=collection_name,
                points=current_batch,
                wait=True,
            )
            completed_ids_list.extend(current_batch_ids)
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
        save_progress(PROGRESS_FILE, completed_ids_list)

    print(f"[OK] Indexación finalizada en colección: {collection_name}")
    print(f"[OK] Total indexados acumulados: {len(completed_ids_list)}")
    print(f"[OK] Progreso guardado en: {PROGRESS_FILE}")

if __name__ == "__main__":
    main()