"""LLM providers for the investigation assistant.

Gemini (Google) is used when GEMINI_API_KEY is set, in the environment or in a project `.env`
file (git-ignored). Model: GEMINI_MODEL, default "gemini-3.8-flash"; backups when it is overloaded:
GEMINI_FALLBACK_MODELS. When it is used, the
retrieved evidence text is sent to Google's API; the answer says so.

Without a key the assistant still answers: `builtin` assembles a grounded answer from the
retrieved records without any language model.
"""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_GEMINI_MODEL = "gemini-3.8-flash"
# Tried in order when the main model is overloaded or silent (comma-separated in GEMINI_FALLBACK_MODELS).
DEFAULT_FALLBACKS = "gemini-3.1-flash-lite,gemini-3.5-flash"


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

    def __init__(self, api_key: str, model: str, timeout_s: float = 60, fallbacks: list[str] | None = None):
        from google import genai
        self.model = model
        self.timeout_s = timeout_s
        self.fallbacks = fallbacks or []
        self.last_model = self.last_route = None
        self._client = genai.Client(api_key=api_key, http_options={"timeout": int(timeout_s * 1000)})

    def generate(self, system: str, prompt: str) -> str:
        # Several attempts inside the overall deadline (GEMINI_TIMEOUT_S): the configured model through the
        # Interactions API, then through the standard generateContent call, then each backup model
        # (GEMINI_FALLBACK_MODELS). Free-tier models are often briefly overloaded (503 UNAVAILABLE) or a
        # single request stalls while a fresh one answers in seconds, so one long wait wastes the budget.
        # Each attempt has a hard wall-clock limit (the SDK timeout only limits each network read); a
        # stalled thread is abandoned. If all fail, answer.py falls back to the built-in answer and says why.
        import concurrent.futures as cf
        import time
        from google.genai import types

        def via_interactions(model):
            r = self._client.interactions.create(model=model, system_instruction=system, input=prompt)
            return getattr(r, "output_text", None)

        def via_generate_content(model):
            r = self._client.models.generate_content(
                model=model, contents=prompt, config=types.GenerateContentConfig(system_instruction=system))
            return r.text

        attempts = [(self.model, "interactions", via_interactions), (self.model, "generate_content", via_generate_content)]
        attempts += [(m, "generate_content", via_generate_content) for m in self.fallbacks if m != self.model]
        deadline = time.monotonic() + self.timeout_s
        per_try = max(10.0, min(25.0, self.timeout_s / 2))
        errors = []
        for model, route, fn in attempts:
            wait = min(per_try, deadline - time.monotonic())
            if wait <= 2:
                break
            pool = cf.ThreadPoolExecutor(max_workers=1)
            fut = pool.submit(fn, model)
            pool.shutdown(wait=False)
            try:
                text = fut.result(timeout=wait)
            except cf.TimeoutError:
                errors.append(f"{model}/{route}: no reply within {wait:.0f} s")
                continue
            except Exception as e:  # overloaded (503), quota (429), model unavailable (404): try the next one
                errors.append(f"{model}/{route}: {type(e).__name__}: {str(e)[:90]}")
                continue
            if text:
                self.last_model, self.last_route = model, route
                return text
            errors.append(f"{model}/{route}: empty reply")
        raise TimeoutError(f"no Gemini model answered within {self.timeout_s:g} s ({'; '.join(errors)})")


def get_llm():
    """The configured LLM, or None (built-in grounded answers)."""
    if (_setting("EVIDENTIA_LLM", "gemini") or "").lower() in ("none", "off", "builtin"):
        return None
    key = _setting("GEMINI_API_KEY") or _setting("GOOGLE_API_KEY")
    if not key:
        return None
    fallbacks = [m.strip() for m in (_setting("GEMINI_FALLBACK_MODELS", DEFAULT_FALLBACKS) or "").split(",") if m.strip()]
    return GeminiLLM(key, _setting("GEMINI_MODEL", DEFAULT_GEMINI_MODEL),
                     float(_setting("GEMINI_TIMEOUT_S", "60")), fallbacks)


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
