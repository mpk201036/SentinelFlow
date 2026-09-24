"""Event ingestion.

adapters/   per-source translation into the canonical schema
parsers     JSON and CSV into raw records, with limits enforced
generator   synthetic events for demonstration and testing
service     orchestration: parse, normalise, validate, store, report
"""

from app.ingestion.adapters import (
    AdapterError,
    SourceAdapter,
    UnknownAdapterError,
    adapter_names,
    detect_adapter,
    get_adapter,
    list_adapters,
    resolve_adapter,
)
from app.ingestion.generator import (
    GeneratedRecord,
    demo_base_time,
    generate_dataset,
    generate_demo_scenario,
    generate_normal_activity,
    group_by_adapter,
)
from app.ingestion.parsers import ParsedRecord, parse_csv_records, parse_json_records
from app.ingestion.service import IngestionOutcome, IngestionService

__all__ = [
    "AdapterError",
    "GeneratedRecord",
    "IngestionOutcome",
    "IngestionService",
    "ParsedRecord",
    "SourceAdapter",
    "UnknownAdapterError",
    "adapter_names",
    "demo_base_time",
    "detect_adapter",
    "generate_dataset",
    "generate_demo_scenario",
    "generate_normal_activity",
    "get_adapter",
    "group_by_adapter",
    "list_adapters",
    "parse_csv_records",
    "parse_json_records",
    "resolve_adapter",
]
