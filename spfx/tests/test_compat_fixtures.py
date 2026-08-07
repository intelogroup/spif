from __future__ import annotations

import json

from compat.generate_compat_fixtures import generate_fixtures
from spfx.reader import SPIFReader
from spfx.streaming import iter_events


def test_generate_fixtures_is_deterministic(tmp_path):
    out1 = tmp_path / "run1"
    out2 = tmp_path / "run2"

    manifest1 = generate_fixtures(out1)
    manifest2 = generate_fixtures(out2)

    assert manifest1 == manifest2

    files1 = sorted(p.name for p in out1.glob("*.spfx"))
    files2 = sorted(p.name for p in out2.glob("*.spfx"))
    assert files1 == files2

    for name in files1:
        assert (out1 / name).read_bytes() == (out2 / name).read_bytes()


def test_fixture_manifest_matches_fixture_bytes(tmp_path):
    out = tmp_path / "fixtures"
    manifest = generate_fixtures(out)
    by_name = {entry["name"]: entry for entry in manifest["fixtures"]}

    assert set(by_name) == {
        "minimal_unsigned",
        "signed_single",
        "multisig",
        "compressed",
        "unknown_chunk",
        "tool_chain",
        "streaming",
        "resumed_streaming",
        "large_compressed_1mb",
    }

    reader = SPIFReader()

    for name, entry in by_name.items():
        path = out / entry["filename"]
        data = path.read_bytes()
        doc = reader.decode(data)

        assert entry["payload_count"] == len(doc.payload)
        assert entry["trace_count"] == len(doc.trace)
        assert entry["bytes"] == len(data)

        features = entry["features"]
        if features["signed"]:
            assert reader.verify_signature(data) is True
        else:
            assert reader.verify_signature(data) is False

        if features.get("streaming"):
            events = list(iter_events(data))
            assert any(event.type == "verified" for event in events)
            if features.get("resumed"):
                resumed = [event for event in events if event.type == "resumed"]
                assert resumed
                assert resumed[0].seq == features["resume_seq"]

    tool_doc = reader.decode((out / by_name["tool_chain"]["filename"]).read_bytes())
    assert tool_doc.payload[0].type == "tool_call"
    assert tool_doc.payload[1].type == "tool_result"
    assert tool_doc.payload[2].refs[0].node_id == "result"


def test_legacy_ref_json_files_match_manifest(tmp_path):
    out = tmp_path / "fixtures"
    manifest = generate_fixtures(out)

    for entry in manifest["fixtures"]:
        ref_path = out / f"{entry['name']}.ref.json"
        assert ref_path.exists()
        ref = json.loads(ref_path.read_text())
        assert ref == entry
