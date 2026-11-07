"""
OASIS SARIF 2.1.0 Reporter for ArmorScan (reporters/sarif.py).
Generates industry-standard Static/Dynamic Analysis Results Interchange Format (SARIF)
files compatible with GitHub Code Scanning / Security tab and Azure DevOps.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Union

from armorscan import __version__
from armorscan.core.models import Finding, ScanResult, Severity

SARIF_SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"


class SarifReporter:
    """Exports ScanResult findings to OASIS SARIF 2.1.0 compliant JSON."""

    @staticmethod
    def _map_level(severity: Severity) -> str:
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        return mapping.get(severity, "warning")

    @staticmethod
    def _map_security_severity(severity: Severity) -> str:
        """Numeric CVSS-equivalent score string required by GitHub Code Scanning."""
        mapping = {
            Severity.CRITICAL: "9.5",
            Severity.HIGH: "8.0",
            Severity.MEDIUM: "5.5",
            Severity.LOW: "3.0",
            Severity.INFO: "1.0",
        }
        return mapping.get(severity, "5.0")

    @classmethod
    def to_dict(cls, result: ScanResult) -> Dict[str, Any]:
        rules: List[Dict[str, Any]] = []
        sarif_results: List[Dict[str, Any]] = []
        seen_rules: Dict[str, int] = {}

        active_findings: List[Finding] = [
            f for f in result.all_findings if not f.is_suppressed
        ]

        for finding in active_findings:
            if finding.id not in seen_rules:
                rule_idx = len(rules)
                seen_rules[finding.id] = rule_idx

                tags = ["security", "dast", finding.module]
                if finding.cwe_id:
                    tags.append(f"external/cwe/{finding.cwe_id.lower()}")
                if finding.owasp_category:
                    tags.append(finding.owasp_category)

                help_markdown = f"### Description\n{finding.description}\n\n### Impact\n{finding.impact}"
                if finding.remediation:
                    help_markdown += f"\n\n### Remediation\n{finding.remediation}"

                rules.append(
                    {
                        "id": finding.id,
                        "name": finding.id,
                        "shortDescription": {"text": finding.title},
                        "fullDescription": {"text": finding.description},
                        "help": {
                            "text": finding.remediation or finding.description,
                            "markdown": help_markdown,
                        },
                        "defaultConfiguration": {
                            "level": cls._map_level(finding.severity),
                        },
                        "properties": {
                            "tags": tags,
                            "precision": finding.confidence.value,
                            "security-severity": cls._map_security_severity(finding.severity),
                            "cwe": finding.cwe_id,
                            "owasp": finding.owasp_category,
                        },
                    }
                )

            rule_index = seen_rules[finding.id]
            target_uri = (
                finding.affected_urls[0]
                if finding.affected_urls
                else result.target.raw_url
            )

            msg_text = f"{finding.title}: {finding.description}"
            if finding.evidence:
                msg_text += f" | Evidence: {finding.evidence}"

            sarif_results.append(
                {
                    "ruleId": finding.id,
                    "ruleIndex": rule_index,
                    "level": cls._map_level(finding.severity),
                    "message": {"text": msg_text},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": target_uri,
                                },
                                "region": {
                                    "startLine": 1,
                                    "startColumn": 1,
                                },
                            }
                        }
                    ],
                    "properties": {
                        "confidence": finding.confidence.value,
                        "module": finding.module,
                        "cwe": finding.cwe_id,
                        "owasp": finding.owasp_category,
                        "curl_command": finding.curl_command,
                    },
                }
            )

        return {
            "$schema": SARIF_SCHEMA_URL,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "ArmorScan",
                            "version": __version__,
                            "informationUri": "https://github.com/AmhetCnaa/ArmorScan",
                            "rules": rules,
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }

    @classmethod
    def export(cls, result: ScanResult, output_path: Union[str, Path]) -> Path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        sarif_data = cls.to_dict(result)
        out.write_text(json.dumps(sarif_data, indent=2, ensure_ascii=False), encoding="utf-8")
        return out
