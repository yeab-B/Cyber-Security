"""Risk scoring engine.

Generates an overall security score (0-100) based on vulnerability findings
and provides severity-based risk assessments.
"""
from typing import List, Dict, Any


# Severity weights for score calculation
SEVERITY_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}

# Maximum deduction per severity level
MAX_DEDUCTIONS = {
    "critical": 60,
    "high": 40,
    "medium": 25,
    "low": 10,
    "info": 0,
}


class RiskEngine:
    """Calculates security risk scores from vulnerability findings."""

    @staticmethod
    def calculate_score(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate overall security score and severity counts.
        
        Returns a dict with:
        - security_score: 0-100 (100 = most secure)
        - critical_count, high_count, medium_count, low_count, info_count
        - risk_level: Critical/High/Medium/Low/Secure
        - total_vulnerabilities
        """
        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "info").lower()
            if severity in counts:
                counts[severity] += 1

        # Calculate deductions
        total_deduction = 0
        for severity, count in counts.items():
            deduction = min(
                count * SEVERITY_WEIGHTS[severity],
                MAX_DEDUCTIONS[severity]
            )
            total_deduction += deduction

        # Calculate score (minimum 0)
        score = max(0, 100 - total_deduction)

        # Determine risk level
        if counts["critical"] > 0 or score < 30:
            risk_level = "Critical"
        elif counts["high"] > 0 or score < 50:
            risk_level = "High"
        elif counts["medium"] > 0 or score < 70:
            risk_level = "Medium"
        elif counts["low"] > 0 or score < 90:
            risk_level = "Low"
        else:
            risk_level = "Secure"

        total = sum(counts.values())

        return {
            "security_score": round(score, 1),
            "risk_level": risk_level,
            "critical_count": counts["critical"],
            "high_count": counts["high"],
            "medium_count": counts["medium"],
            "low_count": counts["low"],
            "info_count": counts["info"],
            "total_vulnerabilities": total,
        }

    @staticmethod
    def get_severity_color(severity: str) -> str:
        """Return hex color for a severity level."""
        colors = {
            "critical": "#EF4444",
            "high": "#F97316",
            "medium": "#EAB308",
            "low": "#3B82F6",
            "info": "#6B7280",
        }
        return colors.get(severity.lower(), "#6B7280")
