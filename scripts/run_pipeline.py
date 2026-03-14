from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = BASE_DIR / "scripts"
STATE_DIR = BASE_DIR / "data" / "state"
STATE_DIR.mkdir(parents=True, exist_ok=True)

REPORT_FILE = STATE_DIR / "pipeline_report.json"

PIPELINE_STEPS: dict[str, str] = {
    "fetch": "fetch_sources.py",
    "preprocess": "preprocessing.py",
    "routing": "routing_generation.py",
    "index": "create_index.py",
}


PIPELINE_ORDER: list[str] = [
    "fetch",
    "preprocess",
    "routing",
    "index",
]


def utc_now_iso() -> str:
    """
    Devuelve la fecha y hora actual

    Returns:
        str: Fecha y hora actual
    """
    return datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M:%S")


def format_duration(seconds: float) -> str:
    """
    Convierte una duración en segundos a un formato legible

    Args:
        seconds (float): Duración en segundos

    Returns:
        str: Duración formateada para lectura humana
    """
    if seconds < 1:
        return f"{int(seconds * 1000)} ms"
    if seconds < 60:
        return f"{seconds:.2f} s"

    minutes = int(seconds // 60)
    remaining_seconds = seconds % 60
    return f"{minutes} min {remaining_seconds:.2f} s"


def save_report(report: dict[str, Any]) -> None:
    """
    Guarda en disco el informe de ejecución del pipeline

    Args:
        report (dict[str, Any]): Diccionario con el resumen de la ejecución

    Returns:
        None
    """
    REPORT_FILE.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def build_empty_report(mode: str, requested_steps: list[str]) -> dict[str, Any]:
    """
    Construye la estructura base del informe del pipeline

    Args:
        mode (str): Modo de ejecución utilizado
        requested_steps (list[str]): Lista de pasos solicitados

    Returns:
        dict[str, Any]: Estructura inicial del informe
    """
    return {
        "started_at": utc_now_iso(),
        "finished_at": None,
        "mode": mode,
        "requested_steps": requested_steps,
        "status": "running",
        "total_duration_seconds": None,
        "steps": [],
        "failed_step": None,
    }


def run_script(step: str, script_name: str) -> dict[str, Any]:
    """
    Ejecuta un script del pipeline y devuelve su resultado estructurado

    Args:
        step (str): Nombre del paso del pipeline
        script_name (str): Nombre del script Python a ejecutar

    Returns:
        dict[str, Any]: Resultado estructurado de la ejecución del paso.
    """
    script_path = SCRIPTS_DIR / script_name

    if not script_path.exists():
        return {
            "step": step,
            "script": script_name,
            "status": "failed",
            "return_code": 1,
            "started_at": utc_now_iso(),
            "finished_at": utc_now_iso(),
            "duration_seconds": 0.0,
            "error": f"No existe el script: {script_path}",
        }

    module_name = f"scripts.{script_path.stem}"
    started_at = utc_now_iso()
    start_time = time.perf_counter()

    print(f"\n[RUN] Paso: {step}")
    print(f"[RUN] Script: {script_name}")
    print(f"[RUN] Módulo: {module_name}")

    try:
        result = subprocess.run(
            [sys.executable, "-m", module_name],
            cwd=str(BASE_DIR),
            check=True,
        )

        duration = time.perf_counter() - start_time
        finished_at = utc_now_iso()

        print(f"[OK] Paso completado: {step} ({format_duration(duration)})")

        return {
            "step": step,
            "script": script_name,
            "status": "completed",
            "return_code": result.returncode,
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_seconds": format_duration(duration),
            "error": None,
        }

    except subprocess.CalledProcessError as exc:
        duration = time.perf_counter() - start_time
        finished_at = utc_now_iso()

        print(f"[ERROR] Paso fallido: {step} ({format_duration(duration)})")
        print(f"[ERROR] Return code: {exc.returncode}")

        return {
            "step": step,
            "script": script_name,
            "status": "failed",
            "return_code": exc.returncode,
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_seconds": format_duration(duration),
            "error": f"El script terminó con código de salida {exc.returncode}",
        }

    except Exception as exc:
        duration = time.perf_counter() - start_time
        finished_at = utc_now_iso()

        print(f"[ERROR] Paso fallido: {step} ({format_duration(duration)})")
        print(f"[ERROR] {exc}")

        return {
            "step": step,
            "script": script_name,
            "status": "failed",
            "return_code": 1,
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_seconds": format_duration(duration),
            "error": str(exc),
        }


def run_steps(steps: list[str], mode: str) -> int:
    """
    Ejecuta una lista de pasos del pipeline en orden. Si hay un erro se para

    Args:
        steps (list[str]): Pasos a ejecutar
        mode (str): Modo de ejecución utilizado para el informe

    Returns:
        int: 0 si la ejecución finaliza correctamente, 1 si falla
    """
    report = build_empty_report(mode=mode, requested_steps=steps)
    pipeline_start = time.perf_counter()

    for step in steps:
        script_name = PIPELINE_STEPS[step]
        step_result = run_script(step=step, script_name=script_name)
        report["steps"].append(step_result)
        save_report(report)

        if step_result["status"] != "completed":
            total_duration = time.perf_counter() - pipeline_start
            report["finished_at"] = utc_now_iso()
            report["status"] = "failed"
            report["failed_step"] = step
            report["total_duration_seconds"] = format_duration(total_duration)
            save_report(report)

            print(f"\n[ABORT] Pipeline detenido en el paso: {step}")
            print(f"[INFO] Reporte guardado en: {REPORT_FILE}")
            return 1

    total_duration = time.perf_counter() - pipeline_start
    report["finished_at"] = utc_now_iso()
    report["status"] = "completed"
    report["total_duration_seconds"] = format_duration(total_duration)
    save_report(report)

    print("\n[OK] Pipeline completado correctamente.")
    print(f"[OK] Duración total: {format_duration(total_duration)}")
    print(f"[INFO] Reporte guardado en: {REPORT_FILE}")
    return 0


def parse_args() -> argparse.Namespace:
    """
    Parsea los argumentos de línea de comandos

    Returns:
        argparse.Namespace: Argumentos parseados
    """
    parser = argparse.ArgumentParser(
        description="Runner del pipeline de threat-intel-vector-db.",
    )

    parser.add_argument(
        "--all",
        action="store_true",
        help="Ejecuta todo el pipeline en orden.",
    )

    parser.add_argument(
        "--step",
        choices=PIPELINE_ORDER,
        help="Ejecuta un único paso del pipeline.",
    )

    parser.add_argument(
        "--steps",
        nargs="+",
        choices=PIPELINE_ORDER,
        help="Ejecuta varios pasos concretos en el orden indicado.",
    )

    parser.add_argument(
        "--list",
        action="store_true",
        help="Muestra los pasos disponibles.",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.list:
        print("Pasos disponibles:")
        for step in PIPELINE_ORDER:
            print(f" - {step}: {PIPELINE_STEPS[step]}")
        sys.exit(0)

    if args.all:
        sys.exit(run_steps(PIPELINE_ORDER, mode="all"))

    if args.step:
        sys.exit(run_steps([args.step], mode="single_step"))

    if args.steps:
        sys.exit(run_steps(args.steps, mode="multiple_steps"))

    print("[INFO] No se indicó ninguna opción.")
    print("Usa una de estas:")
    print("  --all")
    print("  --step fetch")
    print("  --steps fetch preprocess")
    print("  --list")
    sys.exit(1)


if __name__ == "__main__":
    main()