from __future__ import annotations

from pathlib import Path


def preprocess_mitre(raw_file: Path, output_dir: Path) -> int:
    """
    Preprocesa la fuente MITRE ATT&CK.

    Args:
        raw_file (Path): Ruta al fichero raw de MITRE.
        output_dir (Path): Directorio de salida para los chunks.

    Returns:
        int: Número de chunks generados.
    """
    raise NotImplementedError("MITRE preprocessing aún no está implementado.")
    