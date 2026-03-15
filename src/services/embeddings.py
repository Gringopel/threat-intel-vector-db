from __future__ import annotations

import os
from dotenv import load_dotenv
from google import genai

load_dotenv()

EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "models/gemini-embedding-001")

_client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))


def embed_text(text: str) -> list[float]:
    """
    Genera el embedding de un texto usando Gemini Embedding

    Args:
        text (str): Texto de entrada
    
    Returns:
    list[float]: Vector de embedding del texto.
    """
    response = _client.models.embed_content(
        model=EMBEDDING_MODEL,
        contents=text,
    )
    return response.embeddings[0].values