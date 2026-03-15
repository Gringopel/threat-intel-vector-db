from __future__ import annotations

from fastapi import APIRouter, HTTPException

from src.api.schema import ChatRequest, ChatResponse
from src.processes.query_orchestrator import run_rag_query

router = APIRouter(prefix="/chat", tags=["chat"])


@router.post("", response_model=ChatResponse)
async def chat(payload: ChatRequest) -> ChatResponse:
    """
    Endpoint que procesa las preguntas del usuario y devuelve una respuesta de RAG

    Args:
        payload (ChatRequest): Objeto con la pregunta del usuario y parámetros de consulta

    Returns:
        ChatResponse: Respuesta generada junto con las fuentes recuperadas
    """
    try:
        result = await run_rag_query(
            question=payload.question,
            top_k=payload.top_k,
        )
        return ChatResponse(**result)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc