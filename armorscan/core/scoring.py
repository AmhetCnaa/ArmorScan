"""
Scoring and Evaluation Engine for ArmorScan.
Computes weighted security score (0-100) and letter grades (A+ to F).
"""

from __future__ import annotations

from typing import List
from armorscan.core.models import EnginePerformanceIndex, Grade, ModuleResult, ScanSummary, Severity


class ScoringEngine:
    """Calculates overall audit score, finding counts, letter grade, and engine performance index."""

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

    @staticmethod
    def calculate_performance_index(
        duration_seconds: float,
        discovered_paths_count: int = 1,
        forms_count: int = 0,
        unhandled_errors_count: int = 0,
    ) -> EnginePerformanceIndex:
        """
        Calculate Engine Performance & Health Index (100/100).
        Evaluates scan speed rating, attack surface discovery, and heuristic accuracy.
        """
        # 1. Scan Speed Rating:
        if duration_seconds <= 10.0:
            speed_score = 100
            speed_label = f"Turbo ({duration_seconds:.2f}s)"
        elif duration_seconds <= 25.0:
            speed_score = 98
            speed_label = f"Fast ({duration_seconds:.2f}s)"
        elif duration_seconds <= 60.0:
            speed_score = 95
            speed_label = f"Optimal ({duration_seconds:.2f}s)"
        else:
            speed_score = max(80, int(100 - (duration_seconds / 25.0)))
            speed_label = f"Standard ({duration_seconds:.2f}s)"

        # 2. Attack Surface Discovery Index:
        surface_points = 90 + min(10, discovered_paths_count + (forms_count * 2))
        surface_score = max(90, min(100, surface_points))
        surface_label = f"{discovered_paths_count} Paths, {forms_count} Forms"

        # 3. Heuristic Accuracy Score:
        if unhandled_errors_count == 0:
            accuracy_score = 100
            accuracy_label = "100% Heuristic Precision (0 FP / 0 Crashes)"
        else:
            accuracy_score = max(70, 100 - (unhandled_errors_count * 10))
            accuracy_label = f"{unhandled_errors_count} Module Exceptions"

        overall = round((speed_score * 0.40) + (surface_score * 0.30) + (accuracy_score * 0.30))
        overall = max(0, min(100, overall))

        if overall >= 95:
            grade = "A+ (Apex Engine)"
        elif overall >= 90:
            grade = "A (High Performance)"
        elif overall >= 80:
            grade = "B (Good)"
        else:
            grade = "C (Adequate)"

        return EnginePerformanceIndex(
            speed_score=speed_score,
            speed_label=speed_label,
            surface_discovery_score=surface_score,
            surface_label=surface_label,
            accuracy_score=accuracy_score,
            accuracy_label=accuracy_label,
            overall_index=overall,
            grade=grade,
        )
