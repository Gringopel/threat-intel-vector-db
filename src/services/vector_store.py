from __future__ import annotations

import os
from dotenv import load_dotenv
from qdrant_client import QdrantClient

load_dotenv()

QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
QDRANT_COLLECTION = os.getenv("QDRANT_COLLECTION", "threat_intel")

_qdrant_client = QdrantClient(url=QDRANT_URL)


def search_similar(embedding: list[float], limit: int = 5):
    """
    Busca chunks similares en Qdrant a partir de un embedding.
    """
    response = _qdrant_client.query_points(
        collection_name=QDRANT_COLLECTION,
        query=embedding,
        limit=limit,
        with_payload=True,
    )
    return response.points