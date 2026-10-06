"""Coldline.

===================

File:              tests/unit/diagnostics/test_inspect_terms.py
Component:         Diagnostic evidence regression tests
Purpose:           Keep displayed chunk terms consistent with attribution facts.
Interacts With:    Diagnostic inspector and chunk evidence
Sprint/Task:       Sprint 2 — Task 2.8
Concepts:          Evidence consistency, normalized search terms
Tools:             Python 3.12, pytest
"""

from types import SimpleNamespace

import pytest

from tests.diagnostics import inspect
from tests.diagnostics.attribution import chunk_facts


def test_display_uses_title_and_punctuation_normalization(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A title term and a punctuated body term must appear in the same evidence row."""
    texts = {"doc#1": "Beta, gamma!", "doc#2": "Unrelated text."}
    facts = chunk_facts(
        query_text="alpha beta gamma", document_id="doc", title="Alpha", chunk_texts=texts
    )
    monkeypatch.setattr(inspect, "observe", lambda *args: SimpleNamespace(retrieved=False))
    monkeypatch.setattr(inspect, "facts_for", lambda *args: facts)
    monkeypatch.setattr(inspect, "custody_for", lambda *args: None)
    monkeypatch.setattr(inspect, "evidence_lines", lambda *args: [])
    monkeypatch.setattr(inspect, "custody_lines", lambda *args: [])
    monkeypatch.setattr(inspect, "chunk_texts", lambda *args: texts)
    investigation = inspect.Investigation(
        "query", "alpha beta gamma", "tenant", "public", "doc#1", True, "fixture"
    )
    inspect._report(investigation, {"stages": []})
    printed = capsys.readouterr().out
    assert "doc#1  query terms present: ['alpha', 'beta', 'gamma']" in printed
    assert "doc#2  query terms present: ['alpha']" in printed
    assert facts.whole_chunk_ids == ("doc#1",)
    assert "title + body" in printed
