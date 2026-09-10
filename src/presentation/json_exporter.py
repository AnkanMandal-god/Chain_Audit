"""
Layer 3: JSON Exporter for Chain-Mind Auditor.

Produces clean, machine-readable JSON outputs conforming to the schema
for programmatic downstream consumption or API response pipelines.
"""
import json
from typing import Dict, Any


class JSONExporter:
    @staticmethod
    def to_json(data: Dict[str, Any], indent: int = 2) -> str:
        """Serializes dictionary to formatted JSON string."""
        return json.dumps(data, indent=indent)

    @staticmethod
    def print_json(data: Dict[str, Any], indent: int = 2):
        """Prints raw JSON string directly to stdout without formatting or fluff."""
        print(json.dumps(data, indent=indent))
