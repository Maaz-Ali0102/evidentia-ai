"""Sentence embeddings for retrieval and for the relationship mapper's semantic signal.

Primary: all-MiniLM-L6-v2 through fastembed (ONNX, CPU, no PyTorch); the model files are cached in
data/models_cache. Fallback when the model cannot load (offline first run): hashed character
n-gram TF-IDF vectors. The vectors of one cache never mix the two (the model name is stored).

Texts are digit-masked first, so the thousands of near-identical log lines of one template share
one vector (and one computation).
"""
from __future__ import annotations

import threading
from pathlib import Path

import numpy as np

from ..ml.features import mask_digits

ROOT = Path(__file__).resolve().parents[2]
CACHE_DIR = ROOT / "data" / "models_cache"
MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
MAX_CHARS = 512


def norm_text(t: str | None) -> str:
    return mask_digits((t or "")[:MAX_CHARS]).strip()


class Embedder:
    _inst = None
    _lock = threading.Lock()

    def __init__(self):
        self.name = MODEL_NAME
        try:
            from fastembed import TextEmbedding
            self._model = TextEmbedding(MODEL_NAME, cache_dir=str(CACHE_DIR))
        except Exception as e:  # offline or missing package: deterministic fallback
            from sklearn.feature_extraction.text import HashingVectorizer
            self._model = None
            self._hv = HashingVectorizer(analyzer="char_wb", ngram_range=(3, 5), n_features=2 ** 12,
                                         alternate_sign=False, norm="l2")
            self.name = f"hashing-char-3-5 (fallback: {type(e).__name__})"

    @classmethod
    def get(cls) -> "Embedder":
        with cls._lock:
            if cls._inst is None:
                cls._inst = cls()
            return cls._inst

    def embed(self, texts: list[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, 384 if self._model else 2 ** 12), dtype=np.float32)
        if self._model is not None:
            v = np.asarray(list(self._model.embed(texts, batch_size=128)), dtype=np.float32)
        else:
            v = self._hv.transform(texts).toarray().astype(np.float32)
        n = np.linalg.norm(v, axis=1, keepdims=True)
        n[n == 0] = 1.0
        return v / n


def embed_unique(texts: list[str], cache: dict | None = None) -> tuple[np.ndarray, dict]:
    """Embed normalised texts once each. `cache` = {"model", "texts": list, "vecs": array} is
    extended in place-style and returned; rows are looked up with the returned index dict."""
    emb = Embedder.get()
    keys = [norm_text(t) for t in texts]
    if not cache or cache.get("model") != emb.name:
        cache = {"model": emb.name, "texts": [], "vecs": None}
    index = {t: i for i, t in enumerate(cache["texts"])}
    new = sorted({k for k in keys if k not in index})
    if new:
        v = emb.embed(new)
        cache["vecs"] = v if cache["vecs"] is None else np.vstack([cache["vecs"], v])
        for t in new:
            index[t] = len(cache["texts"])
            cache["texts"].append(t)
    return np.array([index[k] for k in keys], dtype=np.int64), cache


def load_cache(path: Path) -> dict | None:
    if not path.exists():
        return None
    z = np.load(path, allow_pickle=False)
    return {"model": str(z["model"]), "texts": list(z["texts"]), "vecs": z["vecs"]}


def save_cache(path: Path, cache: dict) -> None:
    np.savez(path, model=np.array(cache["model"]), texts=np.array(cache["texts"], dtype=object).astype(str),
             vecs=cache["vecs"] if cache["vecs"] is not None else np.zeros((0, 1), np.float32))
