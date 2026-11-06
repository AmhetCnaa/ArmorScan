"""
Scoring and Evaluation Engine for ArmorScan.
Computes weighted security score (0-100) and letter grades (A+ to F).
"""

from __future__ import annotations

from typing import List
from armorscan.core.models import Grade, ModuleResult, ScanSummary, Severity


class ScoringEngine:
    """Calculates overall audit score, finding counts, and letter grade."""

    @staticmethod
    def calculate_summary(modules: List[ModuleResult]) -> ScanSummary:
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        info_count = 0
        suppressed_count = 0
        passed_checks_count = 0

        for mod in modules:
            passed_checks_count += len(mod.passed_checks)
            for finding in mod.findings:
                if finding.is_suppressed:
                    suppressed_count += 1
                    continue

                if finding.severity == Severity.CRITICAL:
                    critical_count += 1
                elif finding.severity == Severity.HIGH:
                    high_count += 1
                elif finding.severity == Severity.MEDIUM:
                    medium_count += 1
                elif finding.severity == Severity.LOW:
                    low_count += 1
                elif finding.severity == Severity.INFO:
                    info_count += 1

        total_findings = critical_count + high_count + medium_count + low_count + info_count
        total_checks = passed_checks_count + total_findings + suppressed_count

        # Calculate penalty
        penalty = (
            (critical_count * Severity.CRITICAL.score_penalty)
            + (high_count * Severity.HIGH.score_penalty)
            + (medium_count * Severity.MEDIUM.score_penalty)
            + (low_count * Severity.LOW.score_penalty)
        )

        final_score = max(0, 100 - penalty)
        grade = Grade.from_score(final_score)

        return ScanSummary(
            total_checks=total_checks,
            passed_checks=passed_checks_count,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            info_count=info_count,
            suppressed_count=suppressed_count,
            score=final_score,
            grade=grade,
        )
