from __future__ import annotations

from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    question: str = Field(..., min_length=3, description="Pregunta del usuario")
    top_k: int = Field(default=5, ge=1, le=10, description="Número de resultados a recuperar")


class RetrievedSource(BaseModel):
    id: str | None = None
    score: float | None = None
    source: str | None = None
    title: str | None = None
    text: str | None = None


class ChatResponse(BaseModel):
    question: str
    answer: str
    sources: list[RetrievedSource]