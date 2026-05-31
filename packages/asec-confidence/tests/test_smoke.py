import pytest
from asec_confidence import (
    BaselineStrategy,
    ConfidenceInputs,
    bm25_recall,
)


def test_imports() -> None:
    from asec_confidence import __version__

    assert __version__ == "0.1.0"


def test_default_weights_sum_to_one() -> None:
    strat = BaselineStrategy()
    assert abs(sum(strat.weights) - 1.0) < 1e-9


def test_weights_must_sum_to_one() -> None:
    with pytest.raises(ValueError):
        BaselineStrategy(weights=(0.5, 0.5, 0.5))


async def test_high_tier_dispatches_specialized() -> None:
    strat = BaselineStrategy()
    result = await strat.score(
        ConfidenceInputs(pattern_match=1.0, memory_recall=1.0, reachability=1.0)
    )
    assert abs(result.score - 1.0) < 1e-9
    assert result.tier == "high"
    assert result.dispatch == "specialized"


async def test_very_low_dispatches_runtime_authorship() -> None:
    strat = BaselineStrategy()
    result = await strat.score(
        ConfidenceInputs(pattern_match=0.0, memory_recall=0.1, reachability=0.0)
    )
    assert result.tier == "very_low"
    assert result.dispatch == "runtime_authorship"


def test_bm25_recall_empty_corpus_is_zero() -> None:
    assert bm25_recall("sql injection", []) == 0.0


def test_bm25_recall_member_beats_nonmember() -> None:
    corpus = [
        "sql injection in the login handler via string concatenation",
        "cross site scripting in the comment renderer",
        "missing rate limiting on the password reset endpoint",
    ]
    member = bm25_recall("sql injection login handler", corpus)
    nonmember = bm25_recall("buffer overflow kernel driver", corpus)
    assert member > nonmember
