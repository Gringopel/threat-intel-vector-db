from __future__ import annotations

from pathlib import Path

from src.preprocessing import preprocess_enisa, preprocess_kev, preprocess_mitre


BASE_DIR = Path(__file__).resolve().parent.parent

RAW_DIR = BASE_DIR / "data" / "raw"
OUTPUT_BASE_DIR = BASE_DIR / "data" / "optimized_chunks"


def main() -> None:
    total_generated = 0

    # KEV
    kev_raw_file = RAW_DIR / "kev" / "known_exploited_vulnerabilities.json"
    kev_output_dir = OUTPUT_BASE_DIR / "kev"

    if kev_raw_file.exists():
        generated = preprocess_kev(kev_raw_file, kev_output_dir)
        total_generated += generated
        print(f"[OK] KEV procesado. Chunks generados: {generated}")
    else:
        print(f"[INFO] KEV no disponible en: {kev_raw_file}")

    # MITRE
    mitre_raw_file = RAW_DIR / "mitre" / "enterprise-attack.json"
    mitre_output_dir = OUTPUT_BASE_DIR / "mitre"

    if mitre_raw_file.exists():
        try:
            generated = preprocess_mitre(mitre_raw_file, mitre_output_dir)
            total_generated += generated
            print(f"[OK] MITRE procesado. Chunks generados: {generated}")
        except NotImplementedError as exc:
            print(f"[INFO] {exc}")
    else:
        print(f"[INFO] MITRE no disponible en: {mitre_raw_file}")

    # ENISA
    enisa_raw_file = RAW_DIR / "enisa" / "enisa_threat_landscape.pdf"
    enisa_output_dir = OUTPUT_BASE_DIR / "enisa"

    if enisa_raw_file.exists():
        try:
            generated = preprocess_enisa(enisa_raw_file, enisa_output_dir)
            total_generated += generated
            print(f"[OK] ENISA procesado. Chunks generados: {generated}")
        except NotImplementedError as exc:
            print(f"[INFO] {exc}")
    else:
        print(f"[INFO] ENISA no disponible en: {enisa_raw_file}")

    print(f"[OK] Total de chunks generados: {total_generated}")


if __name__ == "__main__":
    main()