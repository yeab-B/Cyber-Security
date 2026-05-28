"""AI-assisted security recommendations engine.

Generates detailed remediation guidance for each vulnerability including:
- Risk explanation
- Business impact
- Technical impact
- Recommended fix
- Priority level
"""
from typing import Dict, Any, List


# Knowledge base of security recommendations
RECOMMENDATION_DB = {
    "ssl/tls": {
        "risk_explanation": "SSL/TLS issues expose the application to man-in-the-middle attacks where attackers can intercept, read, and modify data in transit.",
        "business_impact": "Customer data breach, regulatory non-compliance (PCI DSS, GDPR), reputational damage, and potential legal liability.",
        "technical_impact": "Encryption bypass, session hijacking, credential theft, data tampering during transmission.",
        "fix_steps": [
            "Obtain a valid SSL/TLS certificate from a trusted Certificate Authority",
            "Configure TLS 1.2+ with strong cipher suites (ECDHE+AESGCM)",
            "Enable HSTS with long max-age and includeSubDomains",
            "Implement certificate pinning for mobile applications",
            "Disable all SSLv2, SSLv3, TLS 1.0, and TLS 1.1 protocols",
        ],
    },
    "security headers": {
        "risk_explanation": "Missing security headers leave the application vulnerable to various client-side attacks including XSS, clickjacking, and MIME-type confusion.",
        "business_impact": "User account compromise, data theft, defacement, loss of customer confidence.",
        "technical_impact": "Cross-site scripting, clickjacking, MIME-type sniffing attacks, information leakage.",
        "fix_steps": [
            "Implement Content-Security-Policy to prevent XSS attacks",
            "Add X-Frame-Options: DENY to prevent clickjacking",
            "Set X-Content-Type-Options: nosniff to prevent MIME sniffing",
            "Enable Strict-Transport-Security for HTTPS enforcement",
            "Configure Referrer-Policy and Permissions-Policy headers",
        ],
    },
    "cookie security": {
        "risk_explanation": "Insecure cookie configuration can lead to session hijacking and cross-site request forgery attacks.",
        "business_impact": "Unauthorized access to user accounts, financial fraud, data breach.",
        "technical_impact": "Session theft via XSS, CSRF attacks, session fixation.",
        "fix_steps": [
            "Set the Secure flag on all cookies to ensure HTTPS-only transmission",
            "Set HttpOnly flag to prevent JavaScript access to session cookies",
            "Set SameSite=Strict or SameSite=Lax to prevent CSRF",
            "Use short session expiration times",
            "Implement session rotation after authentication",
        ],
    },
    "information disclosure": {
        "risk_explanation": "Exposed server information, technology details, and internal data help attackers map the attack surface and find known vulnerabilities.",
        "business_impact": "Increased likelihood of targeted attacks, faster exploitation of known CVEs.",
        "technical_impact": "Attack surface mapping, version-specific exploit targeting, social engineering enablement.",
        "fix_steps": [
            "Remove or obscure Server header version information",
            "Remove X-Powered-By and other technology-revealing headers",
            "Sanitize error messages to prevent stack trace exposure",
            "Remove HTML comments containing sensitive information",
            "Implement custom error pages without technical details",
        ],
    },
    "permissions": {
        "risk_explanation": "Excessive or dangerous permissions grant the application more access than needed, increasing the risk if the app is compromised.",
        "business_impact": "User privacy violations, regulatory fines, app store removal, loss of user trust.",
        "technical_impact": "Data exfiltration, unauthorized device access, privilege escalation.",
        "fix_steps": [
            "Audit all requested permissions against actual feature requirements",
            "Remove permissions not strictly needed for core functionality",
            "Use runtime permissions for sensitive access (camera, location, etc.)",
            "Implement graceful degradation for denied permissions",
            "Document the purpose of each permission for users",
        ],
    },
    "secrets management": {
        "risk_explanation": "Hardcoded secrets in the application binary can be extracted by anyone who decompiles the APK.",
        "business_impact": "API abuse, unauthorized backend access, financial loss, complete system compromise.",
        "technical_impact": "API key extraction, credential theft, backend compromise, data breach.",
        "fix_steps": [
            "Move all API keys and secrets to a secure backend service",
            "Use Android Keystore system for local credential storage",
            "Implement certificate pinning for API communications",
            "Use environment-specific configuration (no secrets in code)",
            "Rotate all currently-exposed keys and credentials immediately",
        ],
    },
    "build configuration": {
        "risk_explanation": "Debug builds and improper build configuration expose the application to reverse engineering and runtime attacks.",
        "business_impact": "Intellectual property theft, application tampering, unauthorized access.",
        "technical_impact": "Debugger attachment, memory inspection, code injection, data extraction.",
        "fix_steps": [
            "Ensure debuggable is set to false in release builds",
            "Enable code obfuscation with ProGuard/R8",
            "Implement root detection and emulator detection",
            "Use code integrity checks at runtime",
            "Enable application backup encryption or disable backup",
        ],
    },
    "cors": {
        "risk_explanation": "Misconfigured CORS allows unauthorized websites to make requests to the application API.",
        "business_impact": "Data theft from authenticated users, unauthorized API access.",
        "technical_impact": "Cross-origin data theft, CSRF bypass, API abuse.",
        "fix_steps": [
            "Replace wildcard (*) CORS with specific trusted origins",
            "Validate the Origin header on the server side",
            "Restrict allowed methods and headers",
            "Avoid reflecting the Origin header without validation",
            "Implement proper CSRF tokens for state-changing operations",
        ],
    },
    "network security": {
        "risk_explanation": "Insecure network configuration allows traffic interception and exposes data transmitted between the app and servers.",
        "business_impact": "Data interception, credential theft, man-in-the-middle attacks.",
        "technical_impact": "Cleartext traffic interception, certificate validation bypass.",
        "fix_steps": [
            "Implement Network Security Configuration with cleartext traffic disabled",
            "Enable certificate pinning for critical API endpoints",
            "Use TLS 1.2+ for all network communications",
            "Implement proper certificate validation",
            "Monitor for certificate transparency log entries",
        ],
    },
}


class RecommendationsEngine:
    """Generates AI-assisted security recommendations for vulnerabilities."""

    @staticmethod
    def get_recommendation(vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Generate detailed recommendations for a vulnerability."""
        category = vulnerability.get("category", "").lower()
        severity = vulnerability.get("severity", "medium").lower()

        # Find matching recommendation from knowledge base
        recommendation = None
        for key, rec in RECOMMENDATION_DB.items():
            if key in category:
                recommendation = rec
                break

        if not recommendation:
            # Generate generic recommendation
            recommendation = {
                "risk_explanation": f"This {severity}-severity vulnerability could be exploited to compromise application security.",
                "business_impact": "Potential data breach, regulatory non-compliance, and reputational damage.",
                "technical_impact": "Security control bypass, unauthorized access, or data exposure.",
                "fix_steps": [
                    "Review the vulnerability details and affected component",
                    "Apply the specific remediation guidance provided",
                    "Test the fix in a staging environment",
                    "Deploy the fix to production",
                    "Perform a rescan to verify the fix",
                ],
            }

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
            "recommended_fix": "\n".join(f"{i+1}. {step}" for i, step in enumerate(recommendation["fix_steps"])),
            "priority": priority_map.get(severity, "P3 - Normal"),
        }

    @staticmethod
    def enrich_vulnerabilities(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich all vulnerabilities with AI recommendations."""
        engine = RecommendationsEngine()
        for vuln in vulnerabilities:
            rec = engine.get_recommendation(vuln)
            vuln["risk_explanation"] = rec["risk_explanation"]
            vuln["business_impact"] = rec["business_impact"]
            vuln["technical_impact"] = rec["technical_impact"]
            vuln["remediation"] = vuln.get("remediation", "") + "\n\nDetailed Steps:\n" + rec["recommended_fix"]
            vuln["priority"] = rec["priority"]
        return vulnerabilities
