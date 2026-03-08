from __future__ import annotations

import json
from pathlib import Path

from admin_json import load_json

BASE_DIR = Path(__file__).resolve().parent.parent
RAW_FILE = BASE_DIR / "data" / "raw" / "kev" / "known_exploited_vulnerabilities.json"
STATE_DIR = BASE_DIR / "data" / "state"
STATE_DIR.mkdir(parents=True, exist_ok=True)

STATE_FILE = STATE_DIR / "kev_state.json"


def load_state(path: Path) -> dict:
    """Carga el estado previo si existe; en caso contrario devuelve uno vacío."""
    if not path.exists():
        return {}
    return load_json(path)


def save_state(path: Path, state: dict) -> None:
    """Guarda el estado en disco."""
    path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def main() -> None:
    """Compara el hash actual de KEV con el último procesado."""
    if not RAW_FILE.exists():
        raise FileNotFoundError(f"No existe el fichero raw de KEV: {RAW_FILE}")

    payload = load_json(RAW_FILE)
    current_hash = payload.get("_meta", {}).get("sha256")
    catalog_version = payload.get("catalogVersion")
    count = len(payload.get("vulnerabilities", []))

    if not current_hash:
        raise ValueError("No se encontró _meta.sha256 en el JSON raw de KEV.")

    previous_state = load_state(STATE_FILE)
    previous_hash = previous_state.get("sha256")

    changed = current_hash != previous_hash

    new_state = {
        "source": "kev",
        "sha256": current_hash,
        "catalog_version": catalog_version,
        "records": count,
        "changed": changed,
    }
    save_state(STATE_FILE, new_state)

    print(f"[OK] Estado actualizado en: {STATE_FILE}")
    print(f"[INFO] changed={changed}")
    print(f"[INFO] catalog_version={catalog_version}")
    print(f"[INFO] records={count}")


if __name__ == "__main__":
    main()