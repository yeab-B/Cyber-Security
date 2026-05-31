# Design and Implementation of a Web-Based Security Misconfiguration Scanner Using Python

## 1) Project Overview (What, Why, How)

### What is this project?
This project is a beginner-friendly web application built with **Flask + HTML + CSS + Requests + BeautifulSoup**. It scans a target web application (restricted to **localhost/lab environments**) for common security misconfigurations.

### Why is this project useful?
Many real attacks do not start with advanced hacking—they start with simple misconfigurations:
- Open directory listing
- Exposed secret files
- Missing security headers
- Verbose debug errors

Attackers exploit these weaknesses to gather information, steal secrets, or plan deeper attacks.

### How does this scanner work?
1. User enters a target URL in the web form.
2. Flask backend validates that the target is localhost/lab-like.
3. Scanner performs four checks.
4. Results are shown as **Secure (✓)** or **Vulnerable (✗)**.
5. A simple text-based security assessment report is generated.

---

## 2) Full Python Backend Code (Flask)

File: `p_project/B/app.py`

```python
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


# Only allow localhost/lab targets for ethical use.
def is_allowed_target(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False

    host = (parsed.hostname or "").lower()
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True

    return "lab" in host or host.endswith(".local")


# Build a normalized URL and always keep trailing slash behavior predictable.
def normalize_url(url: str) -> str:
    cleaned = url.strip()
    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"http://{cleaned}"
    return cleaned if cleaned.endswith("/") else f"{cleaned}/"


# Helper that safely makes GET requests.
def fetch_url(url: str):
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
        "line ",
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
    app.run(debug=True)
```

---

## 3) Full Frontend Code

### `p_project/B/templates/index.html`
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Security Misconfiguration Scanner</title>
  <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}" />
</head>
<body>
  <main class="container">
    <h1>Web Security Misconfiguration Scanner</h1>
    <p class="lead">
      Educational scanner for <strong>localhost/lab targets only</strong>.
      This tool checks for directory listing, exposed sensitive files,
      missing security headers, and debug information leakage.
    </p>

    <section class="card">
      <h2>Step 1: Enter Target URL</h2>
      <form action="/scan" method="post">
        <label for="target_url">Target URL</label>
        <input
          id="target_url"
          name="target_url"
          type="text"
          placeholder="http://localhost:5001"
          required
        />
        <button type="submit">Start Scan</button>
      </form>
      <p class="hint">Example: http://localhost:5001 or http://test-lab.local</p>
    </section>

    <section class="card">
      <h2>How this scanner works (beginner view)</h2>
      <ol>
        <li><strong>Directory listing check:</strong> Looks for pages that expose file/folder indexes.</li>
        <li><strong>Sensitive file check:</strong> Tries safe requests to common secret file paths like <code>.env</code>.</li>
        <li><strong>Header check:</strong> Verifies important browser protection headers.</li>
        <li><strong>Debug leakage check:</strong> Searches for stack traces and verbose error messages.</li>
      </ol>
    </section>
  </main>
</body>
</html>
```

### `p_project/B/templates/report.html`
```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Scan Report</title>
  <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}" />
</head>
<body>
  <main class="container">
    <h1>Security Scan Report</h1>
    <p class="lead">Target: <code>{{ target_url }}</code></p>

    {% if error %}
      <section class="card error">
        <h2>Scan could not run</h2>
        <p>{{ error }}</p>
      </section>
    {% else %}
      <section class="card">
        <h2>Step 2: Scan Results</h2>
        <table>
          <thead>
            <tr>
              <th>Check</th>
              <th>Status</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {% for item in results %}
            <tr>
              <td>{{ item.name }}</td>
              <td class="status {% if item.secure %}secure{% else %}vulnerable{% endif %}">{{ item.status }}</td>
              <td>
                <ul>
                  {% for detail in item.details %}
                  <li>{{ detail }}</li>
                  {% endfor %}
                </ul>
              </td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </section>

      <section class="card">
        <h2>Step 3: Simple Security Assessment Report</h2>
        <pre>{{ report_text }}</pre>
      </section>
    {% endif %}

    <a class="back-link" href="/">← Run another scan</a>
  </main>
</body>
</html>
```

### `p_project/B/static/style.css`
```css
:root {
  color-scheme: light;
  font-family: Arial, Helvetica, sans-serif;
}

body {
  margin: 0;
  background: #f4f7fb;
  color: #1b2330;
}

.container {
  max-width: 900px;
  margin: 2rem auto;
  padding: 0 1rem;
}

.lead {
  line-height: 1.5;
}

.card {
  background: #fff;
  border: 1px solid #d9e1ee;
  border-radius: 8px;
  padding: 1rem;
  margin: 1rem 0;
}

.error {
  border-color: #c62828;
  background: #fff2f2;
}

label {
  display: block;
  margin-bottom: 0.4rem;
  font-weight: 700;
}

input {
  width: 100%;
  padding: 0.6rem;
  box-sizing: border-box;
  margin-bottom: 0.8rem;
}

button {
  background: #0b5fff;
  color: #fff;
  border: 0;
  border-radius: 6px;
  padding: 0.65rem 1rem;
  cursor: pointer;
}

table {
  width: 100%;
  border-collapse: collapse;
}

th,
td {
  border: 1px solid #d9e1ee;
  text-align: left;
  vertical-align: top;
  padding: 0.6rem;
}

.status.secure {
  color: #146c2e;
  font-weight: 700;
}

.status.vulnerable {
  color: #b42318;
  font-weight: 700;
}

pre {
  white-space: pre-wrap;
  background: #0e1726;
  color: #d2e3ff;
  padding: 1rem;
  border-radius: 6px;
}

.back-link {
  display: inline-block;
  margin-top: 1rem;
}

.hint {
  color: #586174;
  font-size: 0.9rem;
}
```

---

## 4) How to Run Locally (Step by Step)

1. Open terminal and move into the project folder:
   ```bash
   cd p_project/B
   ```

2. (Recommended) create and activate virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate        # Linux/macOS
   # .venv\Scripts\activate         # Windows
   ```

3. Install dependencies:
   ```bash
   pip install flask requests beautifulsoup4
   ```

4. Run the app:
   ```bash
   python app.py
   ```

5. Open browser:
   - `http://127.0.0.1:5000`

6. Enter a **localhost/lab URL** and click **Start Scan**.

---

## 5) Testing Demonstration and Educational Explanation

### Test A: Secure test target (example)
- Target: local app with no directory listing, no exposed `.env`, proper security headers, no stack traces.
- Expected result:
  - Directory listing: ✓ Secure
  - Sensitive files: ✓ Secure
  - Security headers: ✓ Secure
  - Debug exposure: ✓ Secure

### Test B: Intentionally vulnerable lab target (example)
- Target: lab server configured with:
  - Autoindex enabled (`Index of /uploads/` shown)
  - Public `.env`
  - Missing CSP/XFO/XCTO/HSTS
  - Verbose error page with traceback
- Expected result:
  - Directory listing: ✗ Vulnerable
  - Sensitive files: ✗ Vulnerable
  - Security headers: ✗ Vulnerable
  - Debug exposure: ✗ Vulnerable

### Why attackers exploit these findings
- **Directory listing**: reveals hidden files, backup archives, admin scripts.
- **Sensitive file exposure**: `.env` may leak DB passwords, API keys.
- **Missing headers**: increases risk of clickjacking, MIME sniffing, and content injection.
- **Debug leakage**: stack traces expose file paths, code logic, sometimes secrets.

### False positives and limitations
- A page may contain words like “exception” in normal content and trigger debug warning.
- Some servers return custom `200` pages for unknown paths; this can affect sensitive-file detection.
- This project is an educational scanner, not a full commercial scanner.

---

## 6) Final Project Documentation

### 6.1 Introduction
Web security misconfiguration is one of the most common and practical weaknesses in real systems. This project builds a simple scanner to help students identify these weaknesses safely.

### 6.2 Problem Statement
Developers often deploy web apps with insecure default settings (open directories, debug pages, missing headers, exposed files). These mistakes create easy entry points for attackers.

### 6.3 Objectives
1. Build an easy-to-use scanner interface.
2. Detect common misconfigurations automatically.
3. Present results clearly (✓ or ✗).
4. Generate a simple report for learning and assessment.

### 6.4 System Description
- **Input:** URL from user (localhost/lab only)
- **Processing:** Flask backend runs 4 checks using `requests` and `BeautifulSoup`
- **Output:** Scan table + report summary in web UI

### 6.5 Technologies Used
- Python 3
- Flask
- Requests
- BeautifulSoup (bs4)
- HTML + CSS

### 6.6 Functional Requirements
- URL input form
- Ethical target validation (local/lab)
- Directory listing scan
- Sensitive file exposure scan
- Security header validation
- Debug/error leakage detection
- Report generation and display

### 6.7 Security Analysis (OWASP Top 10 Mapping)
Primary OWASP mapping:
- **A05:2021 – Security Misconfiguration**

How each check maps:
- Directory listing exposure → insecure web server configuration
- Exposed `.env/.git/backup` files → improper access control/configuration
- Missing hardening headers → absent browser-side security controls
- Debug traces in production → improper error handling configuration

### 6.8 Expected Outcome
Students can run a local scanner, observe practical findings, and understand how misconfigurations are discovered and exploited during basic penetration testing.

### 6.9 Conclusion
This project demonstrates that simple configuration mistakes can create major security risks. By automating beginner-level checks in a legal and controlled environment, students learn both secure development and ethical penetration testing fundamentals.
