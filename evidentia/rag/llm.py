"""LLM providers for the investigation assistant.

Gemini (Google) is used when GEMINI_API_KEY is set, in the environment or in a project `.env`
file (git-ignored). Model: GEMINI_MODEL, default "gemini-3.8-flash". When it is used, the
retrieved evidence text is sent to Google's API; the answer says so.

Without a key the assistant still answers: `builtin` assembles a grounded answer from the
retrieved records without any language model.
"""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_GEMINI_MODEL = "gemini-3.8-flash"


def _dotenv() -> dict:
    p = ROOT / ".env"
    out = {}
    if p.exists():
        for ln in p.read_text(encoding="utf-8").splitlines():
            ln = ln.strip()
            if ln and not ln.startswith("#") and "=" in ln:
                k, v = ln.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def _setting(name: str, default: str | None = None) -> str | None:
    return os.environ.get(name) or _dotenv().get(name) or default


class GeminiLLM:
    provider = "gemini"
    external = True

    def __init__(self, api_key: str, model: str, timeout_s: float = 60):
        from google import genai
        self.model = model
        self.timeout_s = timeout_s
        self._client = genai.Client(api_key=api_key, http_options={"timeout": int(timeout_s * 1000)})

    def generate(self, system: str, prompt: str) -> str:
        # The SDK timeout limits each network read, not the whole call, so an overloaded
        # model can still hang. A hard wall-clock deadline: on expiry answer.py falls back
        # to the built-in answer and says so in the warnings. The stalled thread is abandoned.
        import concurrent.futures as cf
        pool = cf.ThreadPoolExecutor(max_workers=1)
        fut = pool.submit(self._client.interactions.create, model=self.model,
                          system_instruction=system, input=prompt)
        pool.shutdown(wait=False)
        try:
            r = fut.result(timeout=self.timeout_s)
        except cf.TimeoutError:
            raise TimeoutError(f"no reply from {self.model} within {self.timeout_s:g} s") from None
        text = getattr(r, "output_text", None)
        if not text:
            raise RuntimeError("Gemini returned no text")
        return text


def get_llm():
    """The configured LLM, or None (built-in grounded answers)."""
    if (_setting("EVIDENTIA_LLM", "gemini") or "").lower() in ("none", "off", "builtin"):
        return None
    key = _setting("GEMINI_API_KEY") or _setting("GOOGLE_API_KEY")
    if not key:
        return None
    return GeminiLLM(key, _setting("GEMINI_MODEL", DEFAULT_GEMINI_MODEL),
                     float(_setting("GEMINI_TIMEOUT_S", "60")))


def llm_status() -> dict:
    llm = None
    err = None
    try:
        llm = get_llm()
    except Exception as e:  # package or configuration problem: report, fall back
        err = f"{type(e).__name__}: {e}"
    if llm is None:
        return {"provider": "builtin", "model": None, "external": False,
                "note": err or "No GEMINI_API_KEY set: answers are assembled from retrieved records without an LLM."}
    return {"provider": llm.provider, "model": llm.model, "external": llm.external,
            "note": "Retrieved evidence text is sent to Google's Gemini API to write the answer."}
