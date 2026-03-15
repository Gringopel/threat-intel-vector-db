from __future__ import annotations

from src.services.embeddings import embed_text
from src.services.vector_store import search_similar
from src.services.llms import get_llm


def build_context(results) -> str:
    """
    Construye el contexto a partir de los chunks recuperados

    Args:
        results (list): Resultados devueltos por la búsqueda en la base de datos vectorial.

    Returns:
        str: Texto que se utilizará como contexto para el modelo LLM.
    """
    parts: list[str] = []

    for index, item in enumerate(results, start=1):
        payload = item.payload or {}

        title = payload.get("title", "")
        text = payload.get("text", "")
        source = payload.get("source", payload.get("metadata", {}).get("source", ""))

        parts.append(
            f"[Chunk {index}]\n"
            f"Source: {source}\n"
            f"Title: {title}\n"
            f"Text: {text}"
        )

    return "\n\n".join(parts)


def build_prompt(question: str, context: str) -> str:
    """
    Construye el prompt final de RAG

    Args:
        question (str): Pregunta del usuario
        context (str): Contexto generado a partir de los documentos recuperados

    Returns:
        str: Prompt completo que se enviará al modelo para generar la respuesta
    """
    return f"""
Eres un asistente experto en threat intelligence.

El contexto puede estar en inglés, pero debes responder siempre en español.

Reglas:
- Utiliza únicamente la información del contexto.
- No inventes información.
- Si la respuesta no está en el contexto, indícalo claramente.

Contexto:
{context}

Pregunta:
{question}

Respuesta en español:"""


async def run_rag_query(question: str, top_k: int = 5) -> dict:
    """
    Ejecuta una consulta RAG completa

    Args:
        question (str): Pregunta del usuario
        top_k (int, optional): Número de documentos a recuperar del vector store. Por defecto 5

    Returns:
        dict: Diccionario con la pregunta, la respuesta generada y las fuentes
            utilizadas para construir el contexto
    """
    embedding = embed_text(question)
    results = search_similar(embedding=embedding, limit=top_k)

    context = build_context(results)
    prompt = build_prompt(question=question, context=context)

    llm = get_llm()
    response = await llm.ainvoke(prompt)
    answer = getattr(response, "content", str(response))

    sources: list[dict] = []

    for item in results:
        payload = item.payload or {}
        sources.append(
            {
                "id": str(item.id) if item.id is not None else None,
                "score": float(item.score) if item.score is not None else None,
                "source": payload.get("source", payload.get("metadata", {}).get("source")),
                "title": payload.get("title"),
                "text": payload.get("text"),
            }
        )

    return {
        "question": question,
        "answer": answer,
        "sources": sources,
    }