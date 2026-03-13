from __future__ import annotations

import re
from typing import Any
from dataclasses import dataclass
from pathlib import Path
from pypdf import PdfReader

from src.other_functions import clear_output_directory, normalize_text, safe_slug, save_json
from src.routing.routing_rules import ROUTE_KEYWORDS

BASE_DIR = Path(__file__).resolve().parent.parent
RAW_FILE = BASE_DIR / "data" / "raw" / "kev" / "enisa_threat_landscape.pdf"
OUTPUT_DIR = BASE_DIR / "data" / "optimized_chunks" / "enisa"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# usamos al tabla de contenidos (TOC) como referecia para los chunks
TOC_TEXT = """TABLE OF CONTENTS
1. EXECUTIVE SUMMARY 6
2. METHODOLOGY 7
3. THREAT LANDSCAPE OVERVIEW 8
4. GENERAL KEY TRENDS 11
4.1 PHISHING REMAINS A PRIMARY INITIAL INTRUSION VECTOR 11
4.2 INCREASINGLY TARGETED CYBER DEPENDENCIES 11
4.3 CONTINUOUS TARGETING OF MOBILE DEVICES 12
4.4 THREAT GROUPS CONVERGING 13
4.5 PREDICTABLE USE OF AI 14
5. SECTORIAL ANALYSIS 16
5.1 PUBLIC ADMINISTRATION 17
5.2 TRANSPORT 20
5.3 DIGITAL INFRASTRUCTURE AND SERVICES 22
5.4 FINANCE 25
5.5 MANUFACTURING 26
6. CYBERCRIME 28
6.1 KEY CYBERCRIME THREATS 28
6.2 CYBERCRIME SECTORIAL IMPACT 31
6.3 CYBERCRIME GEOGRAPHICAL IMPACT 32
6.4 KEY CYBERCRIME TRENDS 33
6.4.1 Tactics, Techniques and Procedures (TTPs) 33
6.4.2 Evolution of the ecosystem 34
7. STATE-ALIGNED ACTIVITIES 36
7.1 KEY STATE-ALIGNED THREATS 37
7.1.1 Russia-nexus intrusion sets 37
7.1.2 China-nexus intrusion sets 39
7.1.3 North Korea-nexus intrusion sets 40
7.1.4 Rest of the World (RoW) 41
7.2 KEY STATE-ALIGNED TRENDS 42
7.2.1 Tactics, Techniques and Procedures (TTPs) 42
7.2.2 EU as a target, and as a lure 42
8. FOREIGN INFORMATION MANIPULATION AND INTERFERENCE 44
8.1 KEY FIMI THREATS 44
8.1.1 Russia-aligned Information Manipulation Sets 44
8.1.2 Other Information Manipulation Sets 46
8.2 KEY FIMI TRENDS 46
8.2.1 Tactics, Techniques and Procedures (TTPs) 46
8.2.2 Exploitation of strategic events 47
9. HACKTIVISM 49
9.1 KEY HACKTIVISM THREATS 49
9.2 HACKTIVISM GEOGRAPHICAL TARGETING 51
9.3 HACKTIVISM SECTORIAL TARGETING 52
9.4 KEY HACKTIVISM TRENDS 53
9.4.1 Tactics, Techniques and Procedures (TTPs) 53
9.4.2 Evolution of the ecosystem 54
10. TTPS & VULNERABILITIES 56
10.1 OBSERVED TACTICS, TECHNIQUES & PROCEDURES (TTPS) 56
10.2 VULNERABILITIES 57
10.3 RECOMMENDATIONS 61
10.4 SYSTEM HARDENING 62
10.5 ACCESS & PRIVILEGE 62
10.6 NETWORK PROTECTIONS 62
10.7 MONITORING 62
10.8 RESILIENCE 62
11. OUTLOOK & CONCLUSION 63
12. APPENDIX 64
12.1 TACTICS, TECHNIQUES & PROCEDURES (TTPS) 64
12.2 VULNERABILITIES 81
12.3 LEXICON 85
13. LOG HISTORY 87
"""

MIN_TEXT_LENGTH = 120
MAX_OFFSET_SEARCH = 20
LOCAL_WINDOW = 3


@dataclass(slots=True)
class TocEntry:
    section_id: str
    title: str
    logical_page: int
    level: int
    parent_id: str | None = None
    root_id: str | None = None
    parent_title: str | None = None
    root_title: str | None = None
    is_leaf: bool = True
    actual_page_start: int | None = None
    actual_page_end: int | None = None

    @property
    def hierarchical_title(self) -> str:
        if not self.parent_id:
            return self.title
        
        parts = [
            self.root_title,
            self.parent_title if self.parent_id != self.root_id else None,
            self.title,
        ]
        return " > ".join(part for part in parts if part)


def clean_text(value: str | None) -> str:
    """
    Limpia y normaliza texto extraído del PDF

    Args:
        value (str | None): Texto de entrada

    Returns:
        str: Texto limpio
    """
    if not value:
        return ""

    text = str(value)
    text = text.replace("\n\nENISA THREAT LANDSCAPE 2025 \nTLP:CLEAR | October 2025 \n", "")
    text = text.replace("\r", "\n")
    text = text.replace("\u00ad", "")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def extract_page_texts(reader: PdfReader) -> list[str]:
    """
    Extrae el texto de cada página del PDF

    Args:
        reader (PdfReader): Lector del PDF

    Returns:
        list[str]: Lista de textos por página
    """
    page_texts: list[str] = []

    for page in reader.pages:
        page_text = page.extract_text() or ""
        page_texts.append(clean_text(page_text))

    return page_texts


def get_parent_section(section_id: str) -> str | None:
    """
    Devuelve el identificador de la sección padre

    Args:
        section_id (str): Identificador jerárquico, por ejemplo '6.4.1'

    Returns:
        str | None: Padre inmediato o None si es una sección raíz.
    """
    if "." not in section_id:
        return None
    return section_id.rsplit(".", 1)[0]


def parse_toc(toc_text: str) -> list[TocEntry]:
    """
    Convierte el sumario textual en entradas jerárquicas

    Args:
        toc_text (str): Sumario del documento

    Returns:
        list[TocEntry]: Entradas del índice con jerarquía básica
    """
    entries: list[TocEntry] = []

    for raw_line in toc_text.splitlines():
        line = clean_text(raw_line)
        if not line or line.upper() == "TABLE OF CONTENTS":
            continue
        
        # Regex para separa el número de la sección, el nombre de la seccion y la página
        match = re.match(r"^(\d+(?:\.\d+)*)(?:\.)?\s+(.+?)\s+(\d+)$", line)
        if not match:
            continue

        section_id, title, logical_page = match.groups()
        entries.append(
            TocEntry(
                section_id=section_id,
                title=title.strip(),
                logical_page=int(logical_page),
                level=section_id.count(".") + 1,
            )
        )

    entry_map = {entry.section_id: entry for entry in entries}

    for index, entry in enumerate(entries):
        parent_id = get_parent_section(entry.section_id)
        entry.parent_id = parent_id

        if parent_id and parent_id in entry_map:
            entry.parent_title = entry_map[parent_id].title
            entry.root_id = parent_id.split(".")[0]
            entry.root_title = entry_map[entry.root_id].title if entry.root_id in entry_map else None
        else:
            entry.root_id = entry.section_id
            entry.root_title = entry.title

        if index + 1 < len(entries):
            next_id = entries[index + 1].section_id
            if next_id.startswith(f"{entry.section_id}."):
                entry.is_leaf = False

    return entries


def build_heading_variants(entry: TocEntry) -> list[str]:
    """
    Genera variantes del encabezado para localizarlo en el texto del PDF

    Args:
        entry (TocEntry): Entrada del índice

    Returns:
        list[str]: Posibles variantes del título
    """
    title = clean_text(entry.title)
    section_dot = f"{entry.section_id}. {title}"
    section_plain = f"{entry.section_id} {title}"
    section_tight = f"{entry.section_id}.{title}"
    return [section_dot, section_plain, section_tight, title]


def infer_page_offset(entries: list[TocEntry], page_texts: list[str]) -> int:
    """
    Intenta inferir el offset entre numeración lógica del informe y páginas reales del PDF

    Args:
        entries (list[TocEntry]): Entradas del índice
        page_texts (list[str]): Texto por página del PDF

    Returns:
        int: Offset estimado entre página lógica y real
    """
    normalized_pages = [normalize_text(text) for text in page_texts]
    candidates = [entry for entry in entries if entry.level <= 2][:12]

    best_offset = 0
    best_score = -1

    for offset in range(MAX_OFFSET_SEARCH + 1):
        score = 0
        for entry in candidates:
            actual_index = entry.logical_page - 1 + offset
            if not (0 <= actual_index < len(normalized_pages)):
                continue

            page_blob = normalized_pages[actual_index]
            if any(normalize_text(variant) in page_blob for variant in build_heading_variants(entry)):
                score += 1

        if score > best_score:
            best_score = score
            best_offset = offset

    return best_offset


def find_entry_start_page(
    entry: TocEntry,
    page_texts: list[str],
    normalized_pages: list[str],
    offset: int,
) -> int:
    """
    Busca la página real de inicio para una entrada del índice

    Args:
        entry (TocEntry): Entrada del índice
        page_texts (list[str]): Texto por página del PDF
        normalized_pages (list[str]): Textos normalizados por página
        offset (int): Offset estimado entre página lógica y real

    Returns:
        int: Índice de página real (0-based)
    """
    variants = [normalize_text(variant) for variant in build_heading_variants(entry)]
    expected_page = entry.logical_page - 1 + offset

    # Buscamos el título en varias páginas alrededor de la página que indica el índice
    local_candidates = range(
        max(0, expected_page - LOCAL_WINDOW),
        min(len(page_texts), expected_page + LOCAL_WINDOW + 1),
    )

    for page_index in local_candidates:
        page_blob = normalized_pages[page_index]
        if any(variant and variant in page_blob for variant in variants):
            return page_index

    for page_index, page_blob in enumerate(normalized_pages):
        if any(variant and variant in page_blob for variant in variants):
            return page_index

    return max(0, min(expected_page, len(page_texts) - 1))


def locate_section_pages(entries: list[TocEntry], page_texts: list[str]) -> list[TocEntry]:
    """
    Determina las páginas reales de inicio y fin de cada sección

    Args:
        entries (list[TocEntry]): Entradas del índice
        page_texts (list[str]): Texto por página del PDF

    Returns:
        list[TocEntry]: Entradas con paginación real
    """
    normalized_pages = [normalize_text(text) for text in page_texts]
    offset = infer_page_offset(entries, page_texts)

    for entry in entries:
        entry.actual_page_start = find_entry_start_page(
            entry=entry,
            page_texts=page_texts,
            normalized_pages=normalized_pages,
            offset=offset,
        )

    for index, entry in enumerate(entries):
        current_start = entry.actual_page_start if entry.actual_page_start is not None else 0
        if index + 1 < len(entries):
            next_start = entries[index + 1].actual_page_start
            if next_start is None:
                next_start = current_start
            entry.actual_page_end = max(current_start, next_start - 1)
        else:
            entry.actual_page_end = len(page_texts) - 1

    return entries


def strip_heading_prefix(text: str, entry: TocEntry) -> str:
    """
    Elimina el encabezado de la sección al principio del texto si aparece

    Args:
        text (str): Texto extraído
        entry (TocEntry): Entrada actual

    Returns:
        str: Texto sin el encabezado inicial repetido
    """
    stripped = text.strip()
    patterns = [
        rf"^\s*{re.escape(entry.section_id)}\.\s+{re.escape(entry.title)}\s*",
        rf"^\s*{re.escape(entry.section_id)}\s+{re.escape(entry.title)}\s*",
        rf"^\s*{re.escape(entry.title)}\s*",
    ]

    for pattern in patterns:
        stripped = re.sub(pattern, "", stripped, count=1, flags=re.IGNORECASE)

    return clean_text(stripped)


def slice_section_text(
    entries: list[TocEntry],
    index: int,
    page_texts: list[str],
) -> str:
    """
    Extrae el texto asociado a una sección usando la posición de la sección actual y la siguiente

    Args:
        entries (list[TocEntry]): Entradas ya localizadas
        index (int): Índice de la entrada actual
        page_texts (list[str]): Texto por página del PDF

    Returns:
        str: Texto recortado de la sección
    """
    entry = entries[index]
    start_page = entry.actual_page_start or 0
    end_page = entry.actual_page_end or start_page
    pages = page_texts[start_page : end_page + 1]

    if not pages:
        return ""

    section_text = "\n\n".join(pages)
    normalized_section = normalize_text(section_text)

    current_positions: list[int] = []
    for variant in build_heading_variants(entry):
        position = normalized_section.find(normalize_text(variant))
        if position >= 0:
            current_positions.append(position)

    start_pos = min(current_positions) if current_positions else 0

    next_pos = len(section_text)
    if index + 1 < len(entries):
        next_entry = entries[index + 1]
        candidate_positions: list[int] = []
        for variant in build_heading_variants(next_entry):
            normalized_variant = normalize_text(variant)
            position = normalized_section.find(normalized_variant, start_pos + 1)
            if position >= 0:
                candidate_positions.append(position)
        if candidate_positions:
            next_pos = min(candidate_positions)

    extracted = section_text[start_pos:next_pos].strip()
    return strip_heading_prefix(extracted, entry)


def should_emit_chunk(text: str) -> bool:
    """
    Decide si el texto de una sección tiene entidad suficiente para generar chunk

    Args:
        text (str): Texto de la sección

    Returns:
        bool: True si debe persistirse como chunk
    """
    normalized = clean_text(text)
    if len(normalized) < MIN_TEXT_LENGTH:
        return False

    alnum_count = sum(char.isalnum() for char in normalized)
    return alnum_count >= MIN_TEXT_LENGTH


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


def classify_routes(title: str, hierarchical_title: str, text: str) -> list[str]:
    """
    Clasifica rutas temáticas a partir del título y contenido del chunk.

    Args:
        title (str): Título de la sección.
        hierarchical_title (str): Ruta jerárquica legible.
        text (str): Texto del chunk.

    Returns:
        list[str]: Rutas detectadas.
    """
    blob = normalize_text(" ".join([title, hierarchical_title, text]))
    matched_routes: list[str] = []

    for route_name, keywords in ROUTE_KEYWORDS.items():
        for keyword in keywords:
            if keyword_matches(blob, keyword):
                matched_routes.append(route_name)
                break

    if not matched_routes:
        matched_routes.append("general")

    return sorted(set(matched_routes))


def build_chunk_payload(entry: TocEntry, text: str) -> dict[str, Any]:
    """
    Construye el JSON final del chunk optimizado

    Args:
        entry (TocEntry): Entrada del índice
        text (str): Texto extraído para esa sección

    Returns:
        dict[str, Any]: Chunk optimizado listo para guardar
    """
    hierarchical_title = entry.hierarchical_title or entry.title
    routes = classify_routes(entry.title, hierarchical_title, text)

    metadata: dict[str, Any] = {
        "section_id": entry.section_id,
        "parent_section_id": entry.parent_id,
        "root_section_id": entry.root_id,
        "root_section": entry.root_title,
        "parent_title": entry.parent_title,
        "hierarchical_title": hierarchical_title,
        "page_start": (entry.actual_page_start or 0) + 1,
        "page_end": (entry.actual_page_end or 0) + 1,
        "logical_page": entry.logical_page,
        "level": entry.level,
        "is_leaf": entry.is_leaf,
        "document_type": "threat_report_pdf",
        "report_year": 2025,
        "routes": routes,
    }

    return {
        "id": entry.section_id,
        "source": "enisa",
        "source_type": "pdf_section",
        "title": entry.title,
        "text": text,
        "metadata": metadata,
    }


def preprocess_enisa(raw_file: Path, output_dir: Path) -> int:
    """
    Preprocesa la fuente ENISA y genera chunks optimizados por sección

    Se parsea el sumario, se localiza cada sección en el PDF y se genera un chunk por sección con texto suficiente

    Args:
        raw_file (Path): Ruta al PDF raw de ENISA
        output_dir (Path): Directorio de salida para los chunks

    Returns:
        int: Número de chunks generados.
    """
    if not raw_file.exists():
        raise FileNotFoundError(f"No existe el fichero raw de ENISA: {raw_file}")

    clear_output_directory(output_dir)

    reader = PdfReader(str(raw_file))
    page_texts = extract_page_texts(reader)
    entries = parse_toc(TOC_TEXT)
    entries = locate_section_pages(entries, page_texts)

    total = 0
    for index, entry in enumerate(entries):
        text = slice_section_text(entries=entries, index=index, page_texts=page_texts)

        if not should_emit_chunk(text):
            continue

        chunk = build_chunk_payload(entry=entry, text=text)
        filename = f"{safe_slug(entry.section_id)}__{safe_slug(entry.title)}.json"
        save_json(output_dir / filename, chunk)
        total += 1

    return total
