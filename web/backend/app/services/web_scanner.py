"""Website vulnerability scanner service.

Performs passive security assessments on websites including:
- SSL/TLS validation
- Security headers analysis
- Cookie security analysis
- Server fingerprinting
- HTTP configuration review
- Technology stack identification
"""
import ssl
import socket
import time
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import requests
from requests.exceptions import RequestException
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Required security headers and their descriptions
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "HTTP Strict Transport Security (HSTS) header is missing",
        "impact": "Users may be vulnerable to man-in-the-middle attacks via protocol downgrade",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header",
        "severity": "high",
    },
    "Content-Security-Policy": {
        "description": "Content Security Policy (CSP) header is missing",
        "impact": "The application may be vulnerable to Cross-Site Scripting (XSS) and data injection attacks",
        "remediation": "Implement a Content-Security-Policy header with appropriate directives",
        "severity": "high",
    },
    "X-Content-Type-Options": {
        "description": "X-Content-Type-Options header is missing",
        "impact": "Browser may perform MIME-type sniffing leading to security vulnerabilities",
        "remediation": "Add 'X-Content-Type-Options: nosniff' header",
        "severity": "medium",
    },
    "X-Frame-Options": {
        "description": "X-Frame-Options header is missing",
        "impact": "The application may be vulnerable to clickjacking attacks",
        "remediation": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' header",
        "severity": "medium",
    },
    "X-XSS-Protection": {
        "description": "X-XSS-Protection header is missing",
        "impact": "Browser XSS filter may not be enabled",
        "remediation": "Add 'X-XSS-Protection: 1; mode=block' header",
        "severity": "low",
    },
    "Referrer-Policy": {
        "description": "Referrer-Policy header is missing",
        "impact": "Sensitive information may be leaked through the Referer header",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header",
        "severity": "low",
    },
    "Permissions-Policy": {
        "description": "Permissions-Policy header is missing",
        "impact": "Browser features may be used without restriction by third-party content",
        "remediation": "Add a Permissions-Policy header to control browser feature access",
        "severity": "low",
    },
}


class WebScanner:
    """Performs passive security scanning on web targets."""

    def __init__(self, url: str):
        parsed = urlparse(url)
        if not parsed.scheme:
            url = f"https://{url}"
        self.url = url
        self.parsed_url = urlparse(self.url)
        self.hostname = self.parsed_url.hostname
        self.findings: List[Dict[str, Any]] = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "VulnAssess-Scanner/1.0"
        })
        self.response = None

    def scan(self) -> Dict[str, Any]:
        """Execute all scanning modules and return findings."""
        start_time = time.time()
        
        try:
            self.response = self.session.get(
                self.url, timeout=15, verify=False, allow_redirects=True
            )
        except RequestException as e:
            logger.error(f"Failed to connect to {self.url}: {e}")
            return {
                "target": self.url,
                "error": str(e),
                "vulnerabilities": [],
                "scan_duration": time.time() - start_time,
            }

        # Run all scan modules
        self._check_ssl()
        self._check_security_headers()
        self._check_cookies()
        self._check_server_info()
        self._check_http_methods()
        self._check_technologies()
        self._check_information_disclosure()
        self._check_cors()
        self._check_mixed_content()

        duration = time.time() - start_time
        return {
            "target": self.url,
            "status_code": self.response.status_code,
            "vulnerabilities": self.findings,
            "scan_duration": round(duration, 2),
            "server": self.response.headers.get("Server", "Unknown"),
            "technologies": self._detect_technologies(),
        }

    def _add_finding(self, name: str, severity: str, description: str,
                     impact: str, remediation: str, category: str = "Configuration",
                     evidence: str = "", cve_id: str = None):
        """Add a vulnerability finding."""
        self.findings.append({
            "name": name,
            "severity": severity,
            "category": category,
            "description": description,
            "impact": impact,
            "remediation": remediation,
            "evidence": evidence,
            "cve_id": cve_id,
        })

    def _check_ssl(self):
        """Check SSL/TLS certificate validity and configuration."""
        if self.parsed_url.scheme != "https":
            self._add_finding(
                name="HTTPS Not Enforced",
                severity="critical",
                description="The website does not use HTTPS encryption",
                impact="All data transmitted between the user and server is sent in plaintext and can be intercepted",
                remediation="Obtain and install an SSL/TLS certificate and redirect all HTTP traffic to HTTPS",
                category="SSL/TLS",
            )
            return

        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()

                    # Check protocol version
                    if protocol in ("TLSv1", "TLSv1.1"):
                        self._add_finding(
                            name="Outdated TLS Protocol",
                            severity="high",
                            description=f"Server supports deprecated {protocol} protocol",
                            impact="Vulnerable to known TLS attacks such as BEAST and POODLE",
                            remediation="Disable TLS 1.0 and 1.1, enable TLS 1.2 and TLS 1.3 only",
                            category="SSL/TLS",
                        )

                    # Check certificate expiry
                    import datetime
                    not_after = ssl.cert_time_to_seconds(cert["notAfter"])
                    days_until_expiry = (not_after - time.time()) / 86400
                    if days_until_expiry < 30:
                        self._add_finding(
                            name="SSL Certificate Expiring Soon",
                            severity="medium",
                            description=f"SSL certificate expires in {int(days_until_expiry)} days",
                            impact="Expired certificates cause browser security warnings and loss of user trust",
                            remediation="Renew the SSL/TLS certificate before expiration",
                            category="SSL/TLS",
                            evidence=f"Expires: {cert['notAfter']}",
                        )
        except ssl.SSLError as e:
            self._add_finding(
                name="SSL/TLS Configuration Error",
                severity="high",
                description=f"SSL/TLS error: {str(e)}",
                impact="Secure connections may fail or be vulnerable to attacks",
                remediation="Review and fix SSL/TLS server configuration",
                category="SSL/TLS",
            )
        except Exception as e:
            logger.warning(f"SSL check failed: {e}")

    def _check_security_headers(self):
        """Check for missing security headers."""
        if not self.response:
            return

        for header, info in SECURITY_HEADERS.items():
            if header not in self.response.headers:
                self._add_finding(
                    name=f"Missing {header} Header",
                    severity=info["severity"],
                    description=info["description"],
                    impact=info["impact"],
                    remediation=info["remediation"],
                    category="Security Headers",
                )

    def _check_cookies(self):
        """Analyze cookie security attributes."""
        if not self.response:
            return

        for cookie in self.response.cookies:
            issues = []
            if not cookie.secure:
                issues.append("Secure flag not set")
            if "httponly" not in str(cookie._rest).lower():
                issues.append("HttpOnly flag not set")
            if "samesite" not in str(cookie._rest).lower():
                issues.append("SameSite attribute not set")

            if issues:
                self._add_finding(
                    name=f"Insecure Cookie: {cookie.name}",
                    severity="medium",
                    description=f"Cookie '{cookie.name}' has security issues: {', '.join(issues)}",
                    impact="Session cookies may be vulnerable to theft via XSS or CSRF attacks",
                    remediation="Set Secure, HttpOnly, and SameSite=Strict attributes on all sensitive cookies",
                    category="Cookie Security",
                    evidence=f"Cookie: {cookie.name}, Issues: {', '.join(issues)}",
                )

    def _check_server_info(self):
        """Check for server information disclosure."""
        if not self.response:
            return

        server = self.response.headers.get("Server", "")
        if server and any(v in server.lower() for v in ["apache/", "nginx/", "iis/", "lighttpd/"]):
            self._add_finding(
                name="Server Version Disclosed",
                severity="low",
                description=f"The server reveals its version: {server}",
                impact="Attackers can use version information to find known vulnerabilities",
                remediation="Configure the web server to suppress version information in the Server header",
                category="Information Disclosure",
                evidence=f"Server: {server}",
            )

        powered_by = self.response.headers.get("X-Powered-By", "")
        if powered_by:
            self._add_finding(
                name="Technology Stack Disclosed",
                severity="low",
                description=f"X-Powered-By header reveals: {powered_by}",
                impact="Technology stack information helps attackers target specific vulnerabilities",
                remediation="Remove the X-Powered-By header from server responses",
                category="Information Disclosure",
                evidence=f"X-Powered-By: {powered_by}",
            )

    def _check_http_methods(self):
        """Check for dangerous HTTP methods."""
        try:
            options_resp = self.session.options(self.url, timeout=10)
            allow = options_resp.headers.get("Allow", "")
            dangerous = {"PUT", "DELETE", "TRACE", "CONNECT"}
            found = dangerous.intersection(m.strip() for m in allow.split(","))
            if found:
                self._add_finding(
                    name="Dangerous HTTP Methods Enabled",
                    severity="medium",
                    description=f"Potentially dangerous HTTP methods are enabled: {', '.join(found)}",
                    impact="Attackers may use these methods to modify or delete resources, or perform cross-site tracing",
                    remediation="Disable unnecessary HTTP methods (PUT, DELETE, TRACE, CONNECT) on the web server",
                    category="HTTP Configuration",
                    evidence=f"Allowed methods: {allow}",
                )
        except Exception:
            pass

    def _check_technologies(self):
        """Attempt to identify technology stack from response."""
        # Already handled via _detect_technologies and server info check
        pass

    def _detect_technologies(self) -> List[str]:
        """Detect technologies from response headers and content."""
        techs = []
        if not self.response:
            return techs

        headers = self.response.headers
        body = self.response.text.lower()

        # Header-based detection
        if "X-Powered-By" in headers:
            techs.append(headers["X-Powered-By"])
        if "Server" in headers:
            techs.append(headers["Server"])

        # Body-based detection
        tech_signatures = {
            "react": ["react", "_reactroot", "data-reactroot"],
            "angular": ["ng-app", "ng-controller", "angular.js"],
            "vue.js": ["vue.js", "v-bind", "v-model"],
            "jquery": ["jquery", "jquery.min.js"],
            "bootstrap": ["bootstrap.css", "bootstrap.min.css"],
            "wordpress": ["wp-content", "wp-includes", "wordpress"],
            "drupal": ["drupal.js", "drupal.settings"],
            "django": ["csrfmiddlewaretoken", "__admin"],
            "laravel": ["laravel", "csrf-token"],
        }
        for tech, signatures in tech_signatures.items():
            if any(sig in body for sig in signatures):
                techs.append(tech.title())

        return list(set(techs))

    def _check_information_disclosure(self):
        """Check for information leaks in HTML content."""
        if not self.response:
            return

        body = self.response.text

        # Check for HTML comments with sensitive info
        soup = BeautifulSoup(body, "html.parser")
        comments = soup.find_all(string=lambda text: isinstance(text, type(soup.new_string(""))) and text.parent.name is None)

        # Check for common sensitive patterns
        import re
        sensitive_patterns = {
            "Email Address Exposed": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "Internal IP Address Exposed": r'(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}',
        }

        for name, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, body)
            if matches and len(matches) > 0:
                unique = list(set(matches[:5]))
                self._add_finding(
                    name=name,
                    severity="low",
                    description=f"Potentially sensitive information found in page content",
                    impact="Exposed information can be used for social engineering or targeted attacks",
                    remediation="Review and remove sensitive information from public-facing pages",
                    category="Information Disclosure",
                    evidence=f"Found: {', '.join(unique[:3])}",
                )

    def _check_cors(self):
        """Check CORS misconfiguration."""
        if not self.response:
            return

        acao = self.response.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*":
            self._add_finding(
                name="Permissive CORS Policy",
                severity="medium",
                description="Access-Control-Allow-Origin is set to wildcard (*)",
                impact="Any origin can make cross-origin requests to this application, potentially accessing sensitive data",
                remediation="Restrict CORS to specific trusted origins instead of using wildcard",
                category="CORS",
                evidence=f"Access-Control-Allow-Origin: {acao}",
            )

    def _check_mixed_content(self):
        """Check for mixed content on HTTPS sites."""
        if not self.response or self.parsed_url.scheme != "https":
            return

        soup = BeautifulSoup(self.response.text, "html.parser")
        mixed = []

        for tag in soup.find_all(["script", "link", "img", "iframe"]):
            src = tag.get("src") or tag.get("href", "")
            if src.startswith("http://"):
                mixed.append(src[:80])

        if mixed:
            self._add_finding(
                name="Mixed Content Detected",
                severity="medium",
                description=f"HTTPS page loads {len(mixed)} resource(s) over insecure HTTP",
                impact="Mixed content can be intercepted and modified by attackers, undermining HTTPS security",
                remediation="Ensure all resources are loaded over HTTPS",
                category="SSL/TLS",
                evidence=f"Examples: {', '.join(mixed[:3])}",
            )
