import os

from utils.cache_keys import file_cache_signature, file_set_cache_signature


def test_missing_file_has_no_cache_signature(tmp_path):
    missing = tmp_path / "not-created.csv"
    assert file_cache_signature(missing) is None


def test_signature_changes_when_file_is_rewritten(tmp_path):
    path = tmp_path / "events.csv"
    path.write_text("event_id\nEVT-1\n", encoding="utf-8")
    before = file_cache_signature(path)
    assert before is not None

    path.write_text("event_id,flow_count\nEVT-1,123456\n", encoding="utf-8")
    after = file_cache_signature(path)
    assert after is not None
    assert before != after


def test_file_set_signature_tracks_fallback_candidate_paths(tmp_path):
    primary = tmp_path / "primary.csv"
    fallback = tmp_path / "fallback.csv"
    primary.write_text("a\n1\n", encoding="utf-8")
    before = file_set_cache_signature([primary, fallback])

    fallback.write_text("b\n2\n", encoding="utf-8")
    after = file_set_cache_signature([primary, fallback])

    assert before != after
    assert before[0][1] is not None
    assert before[1][1] is None
    assert after[1][1] is not None


def test_missing_path_signature_changes_after_first_pipeline_write(tmp_path):
    output_path = tmp_path / "pipeline_summary.json"
    before = file_cache_signature(output_path)
    assert before is None

    output_path.write_text('{"mode":"benchmark"}', encoding="utf-8")
    after = file_cache_signature(output_path)
    assert after is not None
    assert before != after
