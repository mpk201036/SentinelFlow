"""MITRE ATT&CK: a local catalogue and evidence-backed mappings.

catalogue   the offline technique and tactic subset SentinelFlow ships
mapper      detections to mappings, refusing anything it cannot justify
"""

from app.mitre.catalogue import (
    CATALOGUE_FILENAME,
    Catalogue,
    Tactic,
    default_catalogue_path,
    get_catalogue,
    load_catalogue,
)
from app.mitre.mapper import (
    MappingResult,
    MitreMapper,
    build_reason,
    tactic_coverage,
    validate_rule_techniques,
)

__all__ = [
    "CATALOGUE_FILENAME",
    "Catalogue",
    "MappingResult",
    "MitreMapper",
    "Tactic",
    "build_reason",
    "default_catalogue_path",
    "get_catalogue",
    "load_catalogue",
    "tactic_coverage",
    "validate_rule_techniques",
]
