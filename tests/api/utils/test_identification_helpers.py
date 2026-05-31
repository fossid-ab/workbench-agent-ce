"""Tests for identification_helpers."""

from workbench_agent.api.utils.identification_helpers import (
    component_identification_record,
    find_first_match,
    find_matches_by_type,
    fossid_match_to_component_fields,
    has_identification_record,
    has_linked_catalog_component,
    parse_identifying_done,
    parse_license_identifiers,
    parse_linked_catalog_components,
    summarize_identification_state,
)

OFP_MATCH = {
    "id": "1329",
    "match_type": "full",
    "author": "OpenFastPath",
    "artifact": "ofp",
    "version": "1.1",
    "purl": "pkg:github/openfastpath/ofp@v1.1",
    "artifact_license": "BSD-3-Clause",
    "artifact_license_category": "PERMISSIVE",
    "file_license": None,
    "url": "https://github.com/OpenFastPath/ofp/archive/refs/tags/v1.1.tar.gz",
}


def test_fossid_match_to_component_fields_uses_artifact_license_and_url():
    fields = fossid_match_to_component_fields(OFP_MATCH)
    assert fields == {
        "component_name": "ofp",
        "component_version": "1.1",
        "supplier_name": "OpenFastPath",
        "license_identifier": "BSD-3-Clause",
        "purl": "pkg:github/openfastpath/ofp@v1.1",
        "url": "https://github.com/OpenFastPath/ofp/archive/refs/tags/v1.1.tar.gz",
        "cpe": None,
    }


def test_fossid_match_to_component_fields_ignores_file_license():
    match = {
        **OFP_MATCH,
        "artifact_license": "AGPL-3.0-only",
        "file_license": "Beerware",
    }
    fields = fossid_match_to_component_fields(match)
    assert fields["license_identifier"] == "AGPL-3.0-only"


def test_fossid_match_to_component_fields_explicit_license_override():
    fields = fossid_match_to_component_fields(
        OFP_MATCH, license_identifier="MIT"
    )
    assert fields["license_identifier"] == "MIT"


def test_identification_record_vs_catalog_link():
    license_only = {
        "component_identification": {
            "id": "1",
            "identifying_done": "0",
            "is_distributed": "1",
        },
        "licenses": {"1": {"license_identifier": "MIT"}},
        "copyright": None,
    }
    assert has_identification_record(license_only) is True
    assert has_linked_catalog_component(license_only) is False

    linked = {
        "component_identification": {
            "components": {
                "25737": {
                    "component_id": 25737,
                    "name": "ofp",
                    "version": "1.1",
                }
            },
            "identifying_done": "1",
        },
        "licenses": False,
        "copyright": "(c) Example",
    }
    assert has_linked_catalog_component(linked) is True
    assert parse_linked_catalog_components(linked)[0]["name"] == "ofp"
    assert parse_identifying_done(linked) is True


def test_summarize_identification_state_includes_agent_fields():
    data = {
        "component_identification": {
            "components": {
                "1": {
                    "name": "ofp",
                    "version": "1.1",
                    "license_identifier": "BSD-3-Clause",
                }
            },
            "identifying_done": "1",
            "is_distributed": "0",
        },
        "licenses": {"1": {"license_identifier": "BSD-3-Clause"}},
        "copyright": "(c) Test",
    }
    summary = summarize_identification_state(data)
    assert summary["has_linked_catalog_component"] is True
    assert summary["linked_catalog_components"][0]["name"] == "ofp"
    assert summary["is_marked_identified"] is True
    assert summary["license_identifiers"] == ["BSD-3-Clause"]
    assert summary["copyright_text"] == "(c) Test"


def test_find_matches_by_type_and_first():
    matches = {
        "1": {"id": "1", "match_type": "partial", "artifact": "a"},
        "2": {"id": "2", "match_type": "full", "artifact": "b"},
    }
    assert len(find_matches_by_type(matches, "partial")) == 1
    full = find_first_match(matches, match_type="full")
    assert full is not None
    assert full["artifact"] == "b"


def test_parse_license_identifiers_empty():
    assert parse_license_identifiers({"licenses": False}) == []
    assert component_identification_record({"component_identification": []}) is None
