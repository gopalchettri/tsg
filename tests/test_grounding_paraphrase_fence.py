"""Calibration paraphrases must survive glm-5 wrapping its JSON array in a markdown fence.

Regression: _paraphrase parsed the reply with a bare json.loads, so a fenced array raised
JSONDecodeError ("Expecting value: line 1 column 1 (char 0)") on EVERY library name. The
POSITIVES set stayed empty, auto-calibration derived its threshold from nothing, and the worker
still spent one sequential LLM call per name doing it -- blocking task consumption for the whole
boot. Provider-side JSON mode cannot cover this: llm.py applies it only for expected_type=dict.
"""
from types import SimpleNamespace

from app.pipeline.grounding import _paraphrase

_FENCED = """```json
["credential theft", "account takeover", "session hijack"]
```"""

_BARE = '["credential theft", "account takeover", "session hijack"]'


class _StubLLM:
    """Minimal stand-in: _paraphrase only calls .chat() and reads the text half."""

    def __init__(self, text: str) -> None:
        self._text = text

    def chat(self, messages, temperature=None, expected_type=None):
        return self._text, None


def _settings():
    # _paraphrase reads exactly one setting; a real Settings() would drag in the env file.
    return SimpleNamespace(calibration_paraphrases_per_name=3)


def test_paraphrase_accepts_fenced_json():
    out = _paraphrase(_StubLLM(_FENCED), "Credential phishing", _settings())
    assert out == ["credential theft", "account takeover", "session hijack"]


def test_paraphrase_still_accepts_bare_json():
    out = _paraphrase(_StubLLM(_BARE), "Credential phishing", _settings())
    assert out == ["credential theft", "account takeover", "session hijack"]


def test_paraphrase_stays_best_effort_on_garbage():
    # Unparseable replies must contribute nothing, never fail calibration.
    assert _paraphrase(_StubLLM("sorry, I cannot do that"), "X", _settings()) == []
