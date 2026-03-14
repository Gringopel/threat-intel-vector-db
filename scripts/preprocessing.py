from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from src.preprocessing import preprocess_enisa, preprocess_kev, preprocess_mitre


BASE_DIR = Path(__file__).resolve().parent.parent

RAW_DIR = BASE_DIR / "data" / "raw"
OUTPUT_BASE_DIR = BASE_DIR / "data" / "optimized_chunks"

STATE_DIR = BASE_DIR / "data" / "state"
STATE_FILE = STATE_DIR / "sources_state.json"


PREPROCESSORS: dict[str, Callable[[Path, Path], int]] = {
    "kev": preprocess_kev,
    "mitre": preprocess_mitre,
    "enisa": preprocess_enisa,
}


RAW_FILES: dict[str, Path] = {
    "kev": RAW_DIR / "kev" / "known_exploited_vulnerabilities.json",
    "mitre": RAW_DIR / "mitre" / "enterprise-attack.json",
    "enisa": RAW_DIR / "enisa" / "enisa_threat_landscape.pdf",
}


OUTPUT_DIRS: dict[str, Path] = {
    "kev": OUTPUT_BASE_DIR / "kev",
    "mitre": OUTPUT_BASE_DIR / "mitre",
    "enisa": OUTPUT_BASE_DIR / "enisa",
}


def utc_now_iso() -> str:
    """Devuelve la fecha actual en formato ISO-8601 UTC"""
    return datetime.now(timezone.utc).isoformat()


def load_state(path: Path) -> dict[str, Any]:
    """Carga el estado global si existe; si no, devuelve uno vacío

    Args:
        path (Path): Ruta del archivo del estado
    """
    if not path.exists():
        return {"sources": {}}
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(path: Path, state: dict[str, Any]) -> None:
    """
    Guarda el estado global en disco
    
    Args:
        path (Path): Ruta del archivo donde se guarda el estado
        state (dict[str, Any]): Datos del estado
    Return:
        None
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(state, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def ensure_source_state(state: dict[str, Any], source: str, raw_file: Path, output_dir: Path) -> dict[str, Any]:
    """
    Garantiza que exista el bloque de estado para una fuente
    
    Args:
        state (dict[str, Any]): Datos del estado
        source (str): Fuente de datos
        raw_file (Path): Archivo con los datos
        output_dir (Path): Directorio donde se guardan los datos de salida
    
    Returns:
        dict[str, Any]: 
    """
    sources = state.setdefault("sources", {})
    source_state = sources.setdefault(source, {})

    source_state.setdefault("source", source)
    source_state.setdefault("raw_file", str(raw_file))
    source_state.setdefault("exists", raw_file.exists())
    source_state.setdefault("changed", raw_file.exists())
    source_state.setdefault("records", 0)
    source_state.setdefault("version", None)
    source_state.setdefault("error", None)

    source_state.setdefault("preprocessing", {})
    source_state["preprocessing"].setdefault("output_dir", str(output_dir))
    source_state["preprocessing"].setdefault("last_run", None)
    source_state["preprocessing"].setdefault("chunks_generated", 0)
    source_state["preprocessing"].setdefault("status", "pending")

    return source_state


def preprocess_source(
    source: str,
    raw_file: Path,
    output_dir: Path,
    preprocessor: Callable[[Path, Path], int],
    source_state: dict[str, Any],
) -> int:
    """
    Ejecuta el preprocesado de una fuente y actualiza su estado
    
    Args:
        source (str): Nombre de la fuente de datos
        raw_file (Path): Ruta al fichero raw descargado de la fuente
        output_dir (Path): Directorio donde se guardarán los chunks optimizados generados
        preprocessor (Callable[[Path, Path], int]): Función encargada de realizar el
            preprocesado de la fuente. Debe recibir (raw_file, output_dir) y devolver
            el número de chunks generados
        source_state (dict[str, Any]): Diccionario que contiene el estado actual de la fuente

    Returns:
        int: Número total de chunks generados durante el preprocesado.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    generated = preprocessor(raw_file, output_dir)

    source_state["exists"] = True
    source_state["error"] = None
    source_state["changed"] = False
    source_state["preprocessing"]["last_run"] = utc_now_iso()
    source_state["preprocessing"]["chunks_generated"] = generated
    source_state["preprocessing"]["status"] = "completed"

    print(f"[OK] {source.upper()} procesado. Chunks generados: {generated}")
    return generated


def main() -> None:
    total_generated = 0
    state = load_state(STATE_FILE)

    for source, preprocessor in PREPROCESSORS.items():
        raw_file = RAW_FILES[source]
        output_dir = OUTPUT_DIRS[source]

        source_state = ensure_source_state(
            state=state,
            source=source,
            raw_file=raw_file,
            output_dir=output_dir,
        )

        if not raw_file.exists():
            source_state["exists"] = False
            source_state["error"] = f"No existe el fichero raw: {raw_file}"
            source_state["preprocessing"]["status"] = "missing_raw"
            print(f"[INFO] {source.upper()} no disponible en: {raw_file}")
            continue

        if not source_state.get("changed", True):
            source_state["preprocessing"]["status"] = "skipped_no_changes"
            print(f"[INFO] {source.upper()} sin cambios. Se omite preprocesado.")
            continue

        try:
            generated = preprocess_source(
                source=source,
                raw_file=raw_file,
                output_dir=output_dir,
                preprocessor=preprocessor,
                source_state=source_state,
            )
            total_generated += generated
        except NotImplementedError as exc:
            source_state["error"] = str(exc)
            source_state["preprocessing"]["status"] = "not_implemented"
            print(f"[INFO] {exc}")
        except Exception as exc:
            source_state["error"] = str(exc)
            source_state["preprocessing"]["status"] = "failed"
            print(f"[ERROR] {source.upper()} fallo en preprocesado: {exc}")

    state["updated_at"] = utc_now_iso()
    save_state(STATE_FILE, state)

    print(f"[OK] Total de chunks generados: {total_generated}")


if __name__ == "__main__":
    main()