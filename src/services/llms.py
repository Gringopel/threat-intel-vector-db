from __future__ import annotations

import os
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI

load_dotenv()


def get_llm() -> ChatGoogleGenerativeAI:
    """
    Devuelve una instancia del LLM configurado para generación.
    """
    return ChatGoogleGenerativeAI(
        model=os.getenv("GENERATION_MODEL", "gemini-2.5-flash-lite"),
        temperature=0.2,
        max_retries=3,
    )