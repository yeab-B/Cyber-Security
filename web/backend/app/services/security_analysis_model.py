"""Dataset-driven security analysis model.

This is a lightweight similarity model that ranks dataset entries using
keyword overlap and metadata hints. It is intentionally simple and
self-contained so the current app can use it without external ML packages.
"""
from functools import lru_cache
import re
from typing import Any, Dict, Iterable, List

from app.services.security_dataset import (
    load_recommendations,
    load_security_headers,
)

TOKEN_RE = re.compile(r"[a-z0-9]+")


def _flatten_values(values: Iterable[Any]) -> str:
    parts: List[str] = []
    for value in values:
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            parts.extend(str(item) for item in value)
        else:
            parts.append(str(value))
    return " ".join(parts)


def _tokenize(*values: Any) -> set[str]:
    text = _flatten_values(values).lower()
    return set(TOKEN_RE.findall(text))


class SecurityAnalysisModel:
    """Rank dataset entries against a vulnerability record."""

    def __init__(self):
        self.security_headers = load_security_headers()
        self.recommendations = load_recommendations()

    def match_recommendation(
        self, vulnerability: Dict[str, Any]
    ) -> Dict[str, Any]:
        query_text = _flatten_values(
            [
                vulnerability.get("name"),
                vulnerability.get("category"),
                vulnerability.get("description"),
                vulnerability.get("impact"),
                vulnerability.get("remediation"),
                vulnerability.get("evidence"),
                vulnerability.get("cve_id"),
            ]
        ).lower()
        query_tokens = _tokenize(
            vulnerability.get("name"),
            vulnerability.get("category"),
            vulnerability.get("description"),
            vulnerability.get("impact"),
            vulnerability.get("remediation"),
            vulnerability.get("evidence"),
            vulnerability.get("cve_id"),
        )

        best_key = ""
        best_entry: Dict[str, Any] = {}
        best_score = -1.0

        for key, entry in self.recommendations.items():
            candidate_tokens = _tokenize(
                key,
                entry.get("aliases", []),
                entry.get("ml_tags", []),
                entry.get("analysis_hints", []),
                entry.get("cwe_ids", []),
            )
            overlap = len(query_tokens & candidate_tokens)
            exact_bonus = 0.0
            if key in query_text:
                exact_bonus += 2.0
            for alias in entry.get("aliases", []):
                if alias in query_text:
                    exact_bonus += 1.0

            score = (
                float(entry.get("confidence", 0.5)) * 0.6
                + min(overlap, 5) * 0.12
                + exact_bonus * 0.1
            )
            score = min(1.0, round(score, 2))
            if score > best_score:
                best_key = key
                best_entry = entry
                best_score = score

        if not best_entry:
            return self._fallback(vulnerability)

        return {
            "matched_dataset_key": best_key,
            "analysis_confidence": round(best_score, 2),
            "ml_tags": best_entry.get("ml_tags", []),
            "cwe_ids": best_entry.get("cwe_ids", []),
            "references": best_entry.get("references", []),
            "risk_explanation": best_entry["risk_explanation"],
            "business_impact": best_entry["business_impact"],
            "technical_impact": best_entry["technical_impact"],
            "recommended_fix": "\n".join(
                f"{index + 1}. {step}"
                for index, step in enumerate(best_entry["fix_steps"])
            ),
        }

    @staticmethod
    def _fallback(vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        severity = vulnerability.get("severity", "medium").lower()
        return {
            "matched_dataset_key": "generic",
            "analysis_confidence": 0.5,
            "ml_tags": [],
            "cwe_ids": [],
            "references": [],
            "risk_explanation": (
                f"This {severity}-severity vulnerability could be "
                "exploited to "
                "compromise application security."
            ),
            "business_impact": (
                "Potential data breach, regulatory non-compliance, and "
                "reputational damage."
            ),
            "technical_impact": (
                "Security control bypass, unauthorized access, or data "
                "exposure."
            ),
            "recommended_fix": "\n".join(
                [
                    (
                        "1. Review the vulnerability details and affected "
                        "component"
                    ),
                    "2. Apply the specific remediation guidance provided",
                    "3. Test the fix in a staging environment",
                    "4. Deploy the fix to production",
                    "5. Perform a rescan to verify the fix",
                ]
            ),
        }


@lru_cache(maxsize=1)
def load_security_analysis_model() -> SecurityAnalysisModel:
    return SecurityAnalysisModel()
