from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from flask import Flask, render_template, request

app = Flask(__name__)

# User-Agent helps some local lab servers respond consistently.
REQUEST_HEADERS = {"User-Agent": "MisconfigScanner/1.0 (Educational Project)"}
TIMEOUT = 5

# Security headers requested in the project requirements.
REQUIRED_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
]

# Common files that should never be publicly accessible.
SENSITIVE_PATHS = [
    ".env",
    ".git/HEAD",
    ".git/config",
    "backup.zip",
    "database.sql",
    "config.php.bak",
]

# Common folders where directory indexing is often misconfigured.
DIRECTORY_PATHS = ["", "uploads/", "images/", "files/", "backup/"]

ALLOWED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1",
    "test-lab.local",
    "dvwa.local",
    "juice-shop.local",
}


# Only allow localhost/lab targets for ethical use.
def is_allowed_target(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False

    if parsed.username or parsed.password:
        return False

    host = (parsed.hostname or "").lower()
    return host in ALLOWED_HOSTS


# Build a normalized URL and always keep trailing slash behavior predictable.
def normalize_url(url: str) -> str:
    cleaned = url.strip()
    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"http://{cleaned}"
    return cleaned if cleaned.endswith("/") else f"{cleaned}/"


# Helper that safely makes GET requests.
def fetch_url(url: str):
    if not is_allowed_target(url):
        return None
    try:
        return requests.get(url, headers=REQUEST_HEADERS, timeout=TIMEOUT, allow_redirects=True)
    except requests.RequestException:
        return None


# Detect directory listing by searching for common listing page patterns.
def check_directory_listing(base_url: str):
    patterns = ["index of /", "directory listing for", "parent directory", "<title>index of"]
    findings = []

    for path in DIRECTORY_PATHS:
        target = urljoin(base_url, path)
        response = fetch_url(target)
        if not response or response.status_code != 200:
            continue

        page_text = response.text.lower()
        soup = BeautifulSoup(response.text, "html.parser")
        page_title = (soup.title.string.lower() if soup.title and soup.title.string else "")

        if any(marker in page_text for marker in patterns) or "index of" in page_title:
            findings.append(f"Possible directory listing exposed at: {target}")

    vulnerable = bool(findings)
    return {
        "name": "Directory Listing",
        "secure": not vulnerable,
        "status": "✓ Secure" if not vulnerable else "✗ Vulnerable",
        "details": findings or ["No obvious directory indexing patterns detected."],
    }


# Check whether sensitive files are exposed via direct requests.
def check_sensitive_files(base_url: str):
    findings = []

    for path in SENSITIVE_PATHS:
        target = urljoin(base_url, path)
        response = fetch_url(target)
        if response and response.status_code == 200 and response.text.strip():
            findings.append(f"Sensitive file may be exposed: {target}")

    vulnerable = bool(findings)
    return {
        "name": "Sensitive File Exposure",
        "secure": not vulnerable,
        "status": "✓ Secure" if not vulnerable else "✗ Vulnerable",
        "details": findings or ["Common sensitive file paths were not publicly accessible."],
    }


# Verify required security response headers.
def check_security_headers(response):
    missing = [header for header in REQUIRED_HEADERS if header not in response.headers]
    vulnerable = bool(missing)

    details = (
        [f"Missing header: {header}" for header in missing]
        if missing
        else ["All required security headers are present."]
    )

    return {
        "name": "HTTP Security Headers",
        "secure": not vulnerable,
        "status": "✓ Secure" if not vulnerable else "✗ Vulnerable",
        "details": details,
    }


# Look for debug traces or verbose server errors.
def check_debug_exposure(base_url: str, response):
    markers = [
        "traceback",
        "exception",
        "stack trace",
        "werkzeug debugger",
        "debug mode",
        "fatal error",
    ]

    findings = []
    lower_body = response.text.lower()
    if any(marker in lower_body for marker in markers):
        findings.append("Potential debug information detected on main page response.")

    invalid_path = urljoin(base_url, "scanner-test-trigger-404")
    invalid_response = fetch_url(invalid_path)
    if invalid_response and any(marker in invalid_response.text.lower() for marker in markers):
        findings.append("Potential debug information detected on error page response.")

    vulnerable = bool(findings)
    return {
        "name": "Debug/Error Information Leakage",
        "secure": not vulnerable,
        "status": "✓ Secure" if not vulnerable else "✗ Vulnerable",
        "details": findings or ["No obvious debug stack traces were found."],
    }


# Convert raw scan checks into a short educational report text.
def build_report_summary(target_url: str, checks):
    vulnerabilities = [check for check in checks if not check["secure"]]

    lines = [
        f"Target: {target_url}",
        f"Total Checks: {len(checks)}",
        f"Potential Issues: {len(vulnerabilities)}",
        "",
        "Findings:",
    ]

    for check in checks:
        lines.append(f"- {check['name']}: {check['status']}")
        for detail in check["details"]:
            lines.append(f"  • {detail}")

    lines.append("")
    lines.append("Note: This scanner is educational and may produce false positives.")
    return "\n".join(lines)


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    url = normalize_url(request.form.get("target_url", ""))

    if not is_allowed_target(url):
        return render_template(
            "report.html",
            target_url=url,
            error="Only localhost or lab-like targets are allowed for ethical testing.",
            results=[],
            report_text="",
        )

    main_response = fetch_url(url)
    if not main_response:
        return render_template(
            "report.html",
            target_url=url,
            error="Target could not be reached. Check that your local/lab site is running.",
            results=[],
            report_text="",
        )

    results = [
        check_directory_listing(url),
        check_sensitive_files(url),
        check_security_headers(main_response),
        check_debug_exposure(url, main_response),
    ]

    report_text = build_report_summary(url, results)
    return render_template("report.html", target_url=url, error=None, results=results, report_text=report_text)


if __name__ == "__main__":
    app.run(debug=False)
