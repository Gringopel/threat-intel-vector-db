import json
import re
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict:
    """Carga un JSON desde disco."""
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, payload: dict[str, Any]) -> None:
    """Guarda un payload JSON en disco."""
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def normalize_text(value: str | None) -> str:
    """
    Elimina espacios, tabulaciones, saltos de linea
    
    Args:
        value (string): Texto a normalizar
        
    Return
        (string) Texto normalizado"""
    if not value:
        return ""
    text = value.lower().strip()
    text = re.sub(r"\s+", " ", text)
    return text
