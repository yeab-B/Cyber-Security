"""AI-assisted security recommendations engine."""
from typing import Dict, Any, List

from app.services.security_analysis_model import load_security_analysis_model
from app.services.security_dataset import load_recommendations


RECOMMENDATION_DB = load_recommendations()
ANALYSIS_MODEL = load_security_analysis_model()


class RecommendationsEngine:
    """Generates AI-assisted security recommendations for vulnerabilities."""

    @staticmethod
    def get_recommendation(vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed recommendations for a vulnerability."""
        severity = vulnerability.get("severity", "medium").lower()

        recommendation = ANALYSIS_MODEL.match_recommendation(vulnerability)

        # Determine priority based on severity
        priority_map = {
            "critical": "P0 - Immediate",
            "high": "P1 - Urgent",
            "medium": "P2 - Important",
            "low": "P3 - Normal",
            "info": "P4 - Informational",
        }

        return {
            "risk_explanation": recommendation["risk_explanation"],
            "business_impact": recommendation["business_impact"],
            "technical_impact": recommendation["technical_impact"],
            "recommended_fix": recommendation["recommended_fix"],
            "priority": priority_map.get(severity, "P3 - Normal"),
            "analysis_confidence": recommendation.get(
                "analysis_confidence",
                0.5,
            ),
            "matched_dataset_key": recommendation.get(
                "matched_dataset_key",
                "generic",
            ),
            "ml_tags": recommendation.get("ml_tags", []),
            "cwe_ids": recommendation.get("cwe_ids", []),
            "references": recommendation.get("references", []),
        }

    @staticmethod
    def enrich_vulnerabilities(
        vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Enrich all vulnerabilities with AI recommendations."""
        engine = RecommendationsEngine()
        for vuln in vulnerabilities:
            rec = engine.get_recommendation(vuln)
            vuln["risk_explanation"] = rec["risk_explanation"]
            vuln["business_impact"] = rec["business_impact"]
            vuln["technical_impact"] = rec["technical_impact"]
            vuln["remediation"] = (
                vuln.get("remediation", "")
                + "\n\nDetailed Steps:\n"
                + rec["recommended_fix"]
            )
            vuln["priority"] = rec["priority"]
            vuln["analysis_confidence"] = rec.get(
                "analysis_confidence",
                0.5,
            )
            vuln["matched_dataset_key"] = rec.get(
                "matched_dataset_key",
                "generic",
            )
            vuln["ml_tags"] = rec.get("ml_tags", [])
            vuln["cwe_ids"] = rec.get("cwe_ids", [])
            vuln["references"] = rec.get("references", [])
        return vulnerabilities
