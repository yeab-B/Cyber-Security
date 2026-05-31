# Module A Documentation

## 1) Architecture and flow

`p_project/A` is a Flask learning project that compares three password storage approaches:
plain text, reversible encryption, and salted hashing with bcrypt.

High-level architecture:

1. **Frontend (HTML/CSS)** renders forms and results (`templates/`, `static/style.css`).
2. **Backend (Flask in `app.py`)** handles routes, validation, and storage logic.
3. **SQLite database (`database.db`)** stores users with `username`, `password_value`, and `method`.

Request/response flow:

1. User opens `/register`.
2. User submits username, password, and storage method.
3. Backend validates input and transforms password based on method.
4. Backend inserts data into SQLite and redirects to `/login` with feedback.
5. User submits login form.
6. Backend verifies password according to stored method (plain/decrypt/bcrypt check).
7. User sees success/failure message.
8. User can open `/attacker` to view simulated leak impact and `/report` for conceptual comparison.

## 2) Backend documentation

### Framework and libraries

- **Flask**: routing and template rendering.
- **sqlite3**: persistence.
- **bcrypt**: secure password hashing.
- **cryptography.fernet**: reversible encryption demo.

### Major backend functions and routes

- `get_fernet()`: builds Fernet key from `FERNET_KEY` env var or derived secret.
- `init_db()`: creates `users` table if missing.
- `encrypt_password()` / `decrypt_password()`: reversible encryption/decryption.
- `hash_password()` / `check_password()`: bcrypt hash and verify.
- `GET /` redirects to `/register`.
- `GET/POST /register`: validates form data, stores user, handles duplicate usernames and invalid method.
- `GET/POST /login`: fetches user and validates password by chosen storage method.
- `GET /attacker`: shows what leaked DB values expose for each method.
- `GET /report`: educational static comparison page.

Validation and error handling:

- Empty username/password is rejected with flash message.
- Unknown storage method is rejected.
- Duplicate usernames are handled via `sqlite3.IntegrityError`.
- Invalid encrypted tokens are handled by `InvalidToken` branch in login.

Security notes:

- Bcrypt is the recommended storage mode.
- Plain/encrypted modes are intentionally included for teaching risks.
- Secret key and Fernet key are environment-driven for safer deployment.

## 3) Frontend documentation

- `templates/register.html`: registration form with method selector.
- `templates/login.html`: login test form and flash feedback.
- `templates/attacker.html`: table that visualizes leak impact.
- `templates/report.html`: conceptual security comparison text.
- `static/style.css`: shared styling for readable beginner UI.

Frontend-backend integration:

- Forms submit with `POST` to Flask routes (`/register`, `/login`).
- Flash messages display backend outcomes (success/failure).
- Jinja templates render dynamic values returned by backend (for example leaked rows).

## 4) How to run Module A (step-by-step)

1. Open terminal and go to module:
   ```bash
   cd p_project/A
   ```
2. Create a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install flask bcrypt cryptography pytest
   ```
4. (Optional but recommended) Set stable keys:
   ```bash
   export FLASK_SECRET_KEY='YOUR_SECRET_KEY_HERE'
   export FERNET_KEY='YOUR_FERNET_KEY_HERE'
   ```
   These are example placeholders only. Before deployment, replace them with strong random values.  
   Example command to generate a valid Fernet key:
   ```bash
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```
5. Start app:
   ```bash
   python app.py
   ```
6. Open browser:
   - `http://127.0.0.1:5000/register`

# Module A Testing

## 1) Backend testing coverage

Automated tests in `p_project/A/tests/test_module_a_app.py` validate:

- Registration + login success for plain mode.
- Rejection of invalid storage method.
- Login failure for wrong password in hashed mode.
- Graceful handling of broken encrypted token (`InvalidToken` path).

Manual backend route checks:

| Route | Input example | Expected result | Actual result |
|---|---|---|---|
| `POST /register` | username=alice, (password), method=plain | User inserted and success flash shown | Matched expected |
| `POST /register` | `method=invalid` | Flash error: invalid method | Matched expected |
| `POST /login` | Existing user + correct password | Success flash | Matched expected |
| `POST /login` | Existing user + wrong password | Failure flash | Matched expected |
| `GET /report` | none | Comparison report page renders | Matched expected |

## 2) Frontend testing coverage

Covered via Flask test client integration:

- Register/login pages return rendered HTML with expected feedback.
- Attacker page displays leak simulation output after registration.
- Flash messages are shown in UI after form submissions.

Manual frontend checks:

| Page | User action | Expected UI output | Actual result |
|---|---|---|---|
| `/register` | Fill and submit form | Redirect to login + success/error flash | Matched expected |
| `/login` | Submit credentials | Success/failure message card | Matched expected |
| `/attacker` | Open after registrations | Table with username/method/db value/attacker outcome | Matched expected |
| `/report` | Open page | Static learning report with 3 storage methods | Matched expected |

## 3) End-to-end integration scenarios

1. Register a user with a storage method.
2. Login with credentials.
3. Verify attacker simulation content for stored method.
4. Confirm security report page is accessible.

## 4) Test execution guide

Run Module A tests:

```bash
cd <repository-root>
python -m pytest p_project/A/tests -q
```

Last executed result:

- `4 passed` for Module A tests (part of combined `9 passed` run).

Success criteria:

- All tests show `passed`.
- No uncaught exceptions.

Failure clues and debugging:

- `ModuleNotFoundError` for Flask/bcrypt/cryptography: install dependencies.
- DB-related failures: ensure tests are run from repository root as shown.
- Template assertion failures: check changed wording in HTML templates/messages.

## 5) Test results summary

| Test ID | Scenario | Status |
|---|---|---|
| A-BE-01 | register + login + attacker flow | Pass |
| A-BE-02 | reject invalid storage method | Pass |
| A-BE-03 | wrong hashed password login fails | Pass |
| A-BE-04 | broken encrypted token handled safely | Pass |

Observations:

- Core route logic and rendering paths are stable for covered scenarios.
- Main limitation: browser-only behavior (CSS rendering) is not visually snapshot-tested.

# Module B Documentation

## 1) Architecture and flow

`p_project/B` is a Flask web scanner for educational misconfiguration checks on local/lab targets only.

Architecture:

1. **Frontend**: form page (`index.html`) + report page (`report.html`).
2. **Backend (`app.py`)**: target validation, HTTP requests, analysis checks, report generation.
3. **External interaction**: requests to target URL using `requests`, then parse content with BeautifulSoup.

Request flow:

1. User opens `/` and enters `target_url`.
2. Form posts to `/scan`.
3. Backend normalizes URL and validates host policy (`localhost`/lab only).
4. Backend fetches target and runs 4 checks:
   - directory listing
   - sensitive files
   - missing security headers
   - debug/error leakage
5. Backend builds human-readable summary text.
6. Frontend displays table of findings and generated report.

Difference from Module A:

- Module A focuses on password storage demonstration with local DB.
- Module B focuses on HTTP security misconfiguration detection for supplied target URLs.

## 2) Backend documentation

Key functions:

- `is_allowed_target(url)`: ethical guardrail; blocks non-lab domains and credentialed URLs.
- `normalize_url(url)`: adds scheme and trailing slash for consistent scanning.
- `fetch_url(url)`: safe HTTP GET wrapper with timeout and exception handling.
- `check_directory_listing(base_url)`: detects exposed directory index patterns.
- `check_sensitive_files(base_url)`: checks common leaked file paths.
- `check_security_headers(response)`: verifies required response headers.
- `check_debug_exposure(base_url, response)`: looks for stack traces/debug markers.
- `build_report_summary(target_url, checks)`: creates final multiline report text.
- `GET /`: index page.
- `POST /scan`: orchestration route for validation + checks + report rendering.

Validation/security handling:

- Restricts scanning to known local/lab hosts.
- Rejects non-HTTP/HTTPS schemes.
- Rejects URLs containing embedded credentials.
- Handles request/network exceptions without crashing.

## 3) Frontend documentation

- `templates/index.html`: scanner introduction + target URL form.
- `templates/report.html`: error block or full check table + generated report text.
- `static/style.css`: visual formatting for cards/table/status indicators.

Integration:

- Form posts to `/scan`.
- Backend passes `error`, `results`, and `report_text` into Jinja template.
- Template conditionally renders failure explanation or successful scan output.

## 4) How to run Module B (step-by-step)

1. Open terminal and move to module:
   ```bash
   cd p_project/B
   ```
2. Create and activate virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install flask requests beautifulsoup4 pytest
   ```
4. Run app:
   ```bash
   python app.py
   ```
5. Open:
   - `http://127.0.0.1:5000`
6. Enter localhost/lab URL and click **Start Scan**. Example accepted formats: `http://localhost:8080` or `http://test-lab.local`.

# Module B Testing

## 1) Backend testing coverage

Automated tests in `p_project/B/tests/test_module_b_app.py` verify:

- Host allow-list and URL normalization behavior.
- Rejection flow for non-lab targets.
- Error flow for unreachable allowed target.
- Successful scan orchestration with expected report data rendering.

Manual backend check matrix:

| Function/route | Input example | Expected result | Actual result |
|---|---|---|---|
| `is_allowed_target()` | `http://localhost:5000` | `True` | Matched expected |
| `is_allowed_target()` | `http://example.com` | `False` | Matched expected |
| `POST /scan` (blocked) | `https://example.com` | Ethical restriction error | Matched expected |
| `POST /scan` (unreachable) | `http://localhost:5001` (service down) | Reachability error | Matched expected |
| `POST /scan` (reachable) | `http://localhost:5001` (mocked) | Findings table + report text | Matched expected |

## 2) Frontend testing coverage

Integration tests assert:

- Index page contains required scan form fields/button.
- Report page renders user-facing error messages.
- Report page renders scan table rows and generated summary text.

Manual frontend checks:

| Page | User action | Expected UI output | Actual result |
|---|---|---|---|
| `/` | Open scanner | URL field + Start Scan button visible | Matched expected |
| `/scan` blocked case | Submit external URL | Error card displayed | Matched expected |
| `/scan` success case | Submit allowed reachable URL | Results table and summary rendered | Matched expected |

## 3) End-to-end integration scenarios

1. Submit a blocked external URL and confirm ethical restriction message.
2. Submit allowed but unreachable local URL and confirm connection error message.
3. Submit allowed reachable URL and confirm findings table + summary appears.

## 4) Test execution guide

Run Module B tests:

```bash
cd <repository-root>
python -m pytest p_project/B/tests -q
```

Last executed result:

- `5 passed` for Module B tests (part of combined `9 passed` run).

Success criteria:

- All tests pass.
- Expected error/success text is rendered for each path.

Debug hints:

- Dependency errors: install Flask/requests/bs4.
- Template mismatch failures: verify expected phrases in HTML after edits.
- Network-related flakiness: tests mock HTTP access; avoid replacing mocks with live targets.

## 5) Test results summary

| Test ID | Scenario | Status |
|---|---|---|
| B-BE-01 | allow-list + URL normalization | Pass |
| B-FE-01 | index page form rendering | Pass |
| B-INT-01 | blocked external target error flow | Pass |
| B-INT-02 | allowed but unreachable target flow | Pass |
| B-INT-03 | successful scan report rendering | Pass |

Observations:

- Validation and route orchestration work as designed in covered cases.
- Limitation: checks are mocked in tests; separate manual labs are still useful for realistic scanner behavior.
