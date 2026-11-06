"""
JSON Reporter for ArmorScan.
Serializes scan results into machine-readable JSON for CI/CD pipelines and SIEM ingestion.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Union

from armorscan.core.models import ScanResult


class JsonReporter:
    """Exports ScanResult to formatted JSON string or file."""

    @staticmethod
    def to_dict(result: ScanResult) -> dict:
        """Convert ScanResult Pydantic model to Python dictionary."""
        return result.model_dump(mode="json")

    @staticmethod
    def to_json(result: ScanResult, indent: int = 2) -> str:
        """Serialize ScanResult to formatted JSON string."""
        return json.dumps(JsonReporter.to_dict(result), indent=indent, ensure_ascii=False)

    @classmethod
    def save(cls, result: ScanResult, output_path: Union[str, Path]) -> str:
        """Write JSON output to target file and return path string."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = cls.to_json(result)
        path.write_text(content, encoding="utf-8")
        return str(path)
