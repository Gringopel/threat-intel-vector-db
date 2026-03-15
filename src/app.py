from __future__ import annotations

from fastapi import FastAPI

from src.api.router_chat import router as chat_router

app = FastAPI(
    title="Threat Intel Vector DB API",
    version="1.0.0",
    description="API RAG para consulta de fuentes de threat intelligence",
)

app.include_router(chat_router)


@app.get("/health", tags=["health"])
def health() -> dict[str, str]:
    return {"status": "ok"}