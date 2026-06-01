"""Tests for IdentificationService."""

from unittest.mock import MagicMock

import pytest

from workbench_agent.api.services.identification_service import (
    IdentificationService,
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


@pytest.fixture
def identification_service():
    files = MagicMock()
    catalog = MagicMock()
    scans = MagicMock()
    return IdentificationService(files, catalog, scans)


FULL_MATCH = {
    "id": "1329",
    "match_type": "full",
    "author": "OpenFastPath",
    "artifact": "ofp",
    "version": "1.1",
    "artifact_license": "BSD-3-Clause",
}


def test_get_identification_delegates(identification_service):
    identification_service._files.get_identification.return_value = {
        "licenses": False
    }
    result = identification_service.get_identification("S1", "src/a.c")
    assert result["licenses"] is False
    identification_service._files.get_identification.assert_called_once_with(
        "S1", "src/a.c"
    )


def test_get_pending_files_delegates(identification_service):
    identification_service._scans.get_pending_files.return_value = {
        "1": "src/a.c"
    }
    pending = identification_service.get_pending_files("S1")
    assert pending == {"1": "src/a.c"}
    identification_service._scans.get_pending_files.assert_called_once_with(
        "S1"
    )


def test_get_scan_metrics_delegates(identification_service):
    identification_service._scans.get_scan_folder_metrics.return_value = {
        "total": 10
    }
    metrics = identification_service.get_scan_metrics("S1")
    assert metrics["total"] == 10


def test_get_identified_components_delegates(identification_service):
    identification_service._scans.get_scan_identified_components.return_value = [
        {"name": "ofp"}
    ]
    components = identification_service.get_identified_components("S1")
    assert len(components) == 1


def test_explore_folder_delegates(identification_service):
    identification_service._files.get_folder_content.return_value = []
    identification_service._files.get_folder_extensions_ranking.return_value = []
    identification_service._files.get_folder_components_ranking.return_value = []

    snapshot = identification_service.explore_folder(
        "S1", "OpenFastPath", pending_only=True
    )

    assert snapshot["path"] == "OpenFastPath"
    identification_service._files.get_folder_content.assert_called_once()
    identification_service._files.get_folder_extensions_ranking.assert_called_once_with(
        "S1", "OpenFastPath", current_view="pending_items"
    )


def test_resolve_component_delegates_to_catalog(identification_service):
    identification_service._catalog.resolve.return_value = {"created": False}
    result = identification_service.resolve_component(
        "ofp", "1.1", "BSD-3-Clause", supplier_name="OpenFastPath"
    )
    assert result["created"] is False
    identification_service._catalog.resolve.assert_called_once_with(
        "ofp",
        "1.1",
        "BSD-3-Clause",
        supplier_name="OpenFastPath",
        purl=None,
        url=None,
        cpe=None,
    )


def test_identify_whole_file_from_match_orchestrates(identification_service):
    identification_service._catalog.resolve.return_value = {
        "component_name": "ofp",
        "component_version": "1.1",
        "supplier_name": "OpenFastPath",
        "created": True,
    }
    identification_service._files.set_identification_component.return_value = {
        "message": "ok"
    }
    identification_service._files.add_license_identification.return_value = {
        "message": "ok"
    }

    result = identification_service.identify_whole_file_from_match(
        "S1", "src/ofp_uma.c", FULL_MATCH
    )

    assert result["catalog"]["created"] is True
    assert result["fields"]["component_name"] == "ofp"
    identification_service._files.set_identification_component.assert_called_once()
    identification_service._files.add_license_identification.assert_called_once()


def test_identify_from_best_full_match_picks_full(identification_service):
    identification_service._files.get_fossid_results.return_value = {
        "1": {"id": "1", "match_type": "partial", "artifact": "x", "version": "1"},
        "2": FULL_MATCH,
    }
    identification_service._catalog.resolve.return_value = {
        "component_name": "ofp",
        "component_version": "1.1",
        "created": False,
    }
    identification_service._files.set_identification_component.return_value = {
        "message": "ok"
    }
    identification_service._files.add_license_identification.return_value = {
        "message": "ok"
    }

    result = identification_service.identify_from_best_full_match(
        "S1", "src/ofp_uma.c", add_file_license=False
    )

    assert result["match"]["match_type"] == "full"
    identification_service._files.add_license_identification.assert_not_called()


def test_identify_snippet_in_file_orchestrates(identification_service):
    match = {
        "author": "OpenFastPath",
        "artifact": "ofp",
        "version": "1.1",
        "file": "src/ofp_uma.c",
    }
    identification_service._files.get_matched_lines.return_value = {
        "local_file": {"10": "10", "11": "11"},
        "mirror_file": {},
    }
    identification_service._files.add_license_identification.return_value = {
        "data": {"identification_id": 1}
    }
    identification_service._files.add_file_comment.return_value = {
        "message": "ok"
    }

    result = identification_service.identify_snippet_in_file(
        "S1", "src/local.c", "BSD-3-Clause", match, "74"
    )

    assert "Lines 10-11" in result["comment_text"]
    identification_service._files.add_license_identification.assert_called_once()
    identification_service._files.add_file_comment.assert_called_once()


def test_set_distribution_status_noop_when_already_set(identification_service):
    identification_service._files.get_identification.return_value = {
        "component_identification": {"is_distributed": "1"},
        "licenses": False,
    }
    result = identification_service.set_distribution_status(
        "S1", "src/a.c", distributed=True
    )
    assert result["changed"] is False
    identification_service._files.change_distribution_status.assert_not_called()


def test_mark_as_identified_includes_parsed_state(identification_service):
    identification_service._files.mark_as_identified.return_value = {
        "message": "ok"
    }
    identification_service._files.get_identification.return_value = {
        "component_identification": {"identifying_done": "1"},
        "licenses": False,
    }
    result = identification_service.mark_as_identified("S1", "src/a.c")
    assert result["is_marked_identified"] is True


def test_summarize_identification_data_parses_match_fields(
    identification_service,
):
    identification_service._catalog.resolve.return_value = {"created": True}
    result = identification_service.resolve_component_from_match(OFP_MATCH)
    identification_service._catalog.resolve.assert_called_once()
    call_args = identification_service._catalog.resolve.call_args
    assert call_args[0][0] == "ofp"
    assert call_args[0][1] == "1.1"
    assert call_args[0][2] == "BSD-3-Clause"
    assert call_args[1]["url"] == OFP_MATCH["url"]
    assert result["created"] is True


def test_summarize_identification_data_license_only_vs_linked(
    identification_service,
):
    license_only = {
        "component_identification": {
            "id": "1",
            "identifying_done": "0",
            "is_distributed": "1",
        },
        "licenses": {"1": {"license_identifier": "MIT"}},
        "copyright": None,
    }
    summary = identification_service.summarize_identification_data(license_only)
    assert summary["has_identification_record"] is True
    assert summary["has_linked_catalog_component"] is False

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
    summary = identification_service.summarize_identification_data(linked)
    assert summary["has_linked_catalog_component"] is True
    assert summary["linked_catalog_components"][0]["name"] == "ofp"
    assert summary["is_marked_identified"] is True


def test_summarize_identification_data_includes_agent_fields(
    identification_service,
):
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
    summary = identification_service.summarize_identification_data(data)
    assert summary["has_linked_catalog_component"] is True
    assert summary["linked_catalog_components"][0]["name"] == "ofp"
    assert summary["is_marked_identified"] is True
    assert summary["license_identifiers"] == ["BSD-3-Clause"]
    assert summary["copyright_text"] == "(c) Test"


def test_summarize_identification_data_empty_licenses(
    identification_service,
):
    summary = identification_service.summarize_identification_data(
        {"licenses": False, "component_identification": []}
    )
    assert summary["license_identifiers"] == []
    assert summary["has_identification_record"] is False

