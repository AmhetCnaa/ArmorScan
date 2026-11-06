"""
Suppression Engine for ArmorScan (.armorscanignore).
Filters out deliberately accepted or grandfathered security findings based on
finding ID, URL pattern regex, expiration dates, and human justifications.
"""

from __future__ import annotations

from datetime import date, datetime
from pathlib import Path
import re
from typing import Any, Dict, List, Optional
import yaml

from armorscan.core.models import Finding


class SuppressionRule:
    """Individual rule for suppressing a known finding."""

    def __init__(
        self,
        finding_id: str,
        url_pattern: str = ".*",
        reason: str = "No justification provided",
        expires: Optional[str] = None,
    ):
        self.finding_id = finding_id.strip()
        self.url_pattern_str = url_pattern.strip()
        self.url_regex = re.compile(self.url_pattern_str, re.IGNORECASE)
        self.reason = reason.strip()
        self.expires_str = expires.strip() if expires else None

        self.expiration_date: Optional[date] = None
        if self.expires_str:
            try:
                self.expiration_date = datetime.strptime(self.expires_str, "%Y-%m-%d").date()
            except ValueError:
                self.expiration_date = None

    @property
    def is_expired(self) -> bool:
        if self.expiration_date is None:
            return False
        return date.today() > self.expiration_date

    def matches(self, finding: Finding, target_url: str) -> bool:
        """Evaluate whether this suppression rule applies to the finding."""
        if self.is_expired:
            return False

        # Match finding ID (supporting wildcard *)
        if self.finding_id != "*" and self.finding_id.upper() != finding.id.upper():
            return False

        # Match URL pattern
        if not self.url_regex.search(target_url):
            return False

        return True


class SuppressionEngine:
    """Loads and applies .armorscanignore rules against findings."""

    def __init__(self, rules: Optional[List[SuppressionRule]] = None):
        self.rules: List[SuppressionRule] = rules or []

    @classmethod
    def from_file(cls, path: Path) -> SuppressionEngine:
        """Parse rules from a YAML or line-based .armorscanignore file."""
        if not path.exists():
            return cls(rules=[])

        try:
            content = path.read_text(encoding="utf-8")
        except Exception:
            return cls(rules=[])

        rules: List[SuppressionRule] = []

        # 1. Attempt YAML parsing
        try:
            parsed = yaml.safe_load(content)
            if isinstance(parsed, dict) and "suppressions" in parsed:
                for item in parsed["suppressions"]:
                    if isinstance(item, dict) and "id" in item:
                        rules.append(
                            SuppressionRule(
                                finding_id=str(item["id"]),
                                url_pattern=str(item.get("url_pattern", ".*")),
                                reason=str(item.get("reason", "Accepted risk")),
                                expires=item.get("expires"),
                            )
                        )
                if rules:
                    return cls(rules=rules)
        except Exception:
            pass

        # 2. Fallback to line-based parsing: ID | URL_PATTERN | REASON | EXPIRES
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-") or line.endswith(":") or line.startswith("suppressions"):
                continue

            parts = [p.strip() for p in line.split("|")]
            rule_id = parts[0]
            if not rule_id:
                continue
            url_pattern = parts[1] if len(parts) > 1 and parts[1] else ".*"
            reason = parts[2] if len(parts) > 2 and parts[2] else "Suppressed via .armorscanignore"
            expires = parts[3] if len(parts) > 3 and parts[3] else None

            rules.append(
                SuppressionRule(
                    finding_id=rule_id,
                    url_pattern=url_pattern,
                    reason=reason,
                    expires=expires,
                )
            )

        return cls(rules=rules)

    @classmethod
    def find_and_load(cls, custom_path: Optional[str] = None, search_dir: Optional[Path] = None) -> SuppressionEngine:
        """Locate and load .armorscanignore from custom path, search_dir, or current workspace."""
        if custom_path:
            p = Path(custom_path)
            if p.exists():
                return cls.from_file(p)

        base = search_dir or Path.cwd()
        candidate = base / ".armorscanignore"
        if candidate.exists():
            return cls.from_file(candidate)

        return cls(rules=[])

    def apply_to_findings(self, findings: List[Finding], target_url: str) -> None:
        """Mark matching findings as suppressed with justification."""
        for finding in findings:
            for rule in self.rules:
                if rule.matches(finding, target_url):
                    finding.is_suppressed = True
                    finding.suppression_reason = rule.reason
                    break
