from __future__ import annotations

from pathlib import Path


def preprocess_enisa(raw_file: Path, output_dir: Path) -> int:
    """
    Preprocesa la fuente ENISA.

    Args:
        raw_file (Path): Ruta al fichero raw de ENISA.
        output_dir (Path): Directorio de salida para los chunks.

    Returns:
        int: Número de chunks generados.
    """
    raise NotImplementedError("ENISA preprocessing aún no está implementado.")