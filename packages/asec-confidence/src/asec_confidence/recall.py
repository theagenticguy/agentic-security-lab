"""Lexical recall axis: a thin BM25 wrapper normalised to ``[0, 1]``.

``bm25s`` ships no type stubs, so the calls into it are confined to
:func:`_top_bm25_score`, which casts the untyped result back to a ``float`` at
the package boundary.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from typing import Any

import bm25s  # pyright: ignore[reportMissingTypeStubs]
import structlog
from opentelemetry import trace

_log = structlog.get_logger(__name__)
_tracer = trace.get_tracer(__name__)


def _top_bm25_score(query: str, documents: list[str]) -> float:
    """Return the raw BM25 score of the best-matching document for ``query``.

    All access to the untyped ``bm25s`` surface is funnelled through ``_bm`` so
    the unknown types stay contained behind this single boundary cast.
    """
    bm: Any = bm25s
    corpus_tokens: Any = bm.tokenize(documents, show_progress=False)
    retriever: Any = bm.BM25()
    retriever.index(corpus_tokens, show_progress=False)

    query_tokens: Any = bm.tokenize(query, show_progress=False)
    _results, scores = retriever.retrieve(query_tokens, k=1, show_progress=False)
    scores_any: Any = scores
    if not int(scores_any.size):
        return 0.0
    return float(scores_any[0, 0])


def bm25_recall(query: str, corpus: Iterable[str]) -> float:
    """Score how well ``query`` is recalled from ``corpus`` in ``[0, 1]``.

    Builds an ephemeral BM25 index over ``corpus``, retrieves against
    ``query``, and squashes the top raw BM25 score through a sigmoid so the
    result is bounded and monotonic in match strength. Returns ``0.0`` for an
    empty corpus or a query that matches nothing.
    """
    with _tracer.start_as_current_span("bm25_recall"):
        documents = [doc for doc in corpus if doc]
        if not documents:
            return 0.0

        top = _top_bm25_score(query, documents)
        if top <= 0.0:
            return 0.0
        # Sigmoid squash keeps the axis in (0, 1) and monotonic in BM25 score.
        recall = 1.0 / (1.0 + math.exp(-top))
        _log.info("bm25_recall", top_score=top, recall=recall, corpus_size=len(documents))
        return recall
