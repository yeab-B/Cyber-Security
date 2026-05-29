# How It Works

## 1. User Authentication

Users register or log in through the frontend. The authentication API returns a bearer token, and the frontend stores that token in local storage. Every scan, dashboard request, report request, and admin action uses the token for authorization.

### Main auth endpoints

- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/me`
- `PUT /api/auth/me`
- `POST /api/auth/change-password`

## 2. Start a Scan

The dashboard offers two scan types:

- Web assessment for remote domains
- APK assessment for Android application packages

A scan record is created in the database before analysis begins. The scan status is initially marked as running.

### Web scan flow

1. The user submits a target URL.
2. The backend creates a scan record.
3. `WebScanner` connects to the site and performs passive checks.
4. Findings are enriched with remediation guidance.
5. `RiskEngine` calculates the security score and severity counts.
6. Findings are stored and the scan is marked complete.

### APK scan flow

1. The user uploads an `.apk` file.
2. The backend validates the extension and file size.
3. The file is saved temporarily to the upload directory.
4. `APKScanner` performs static analysis on the manifest, permissions, DEX strings, and package contents.
5. Findings are enriched and scored.
6. The uploaded file is deleted after analysis.

## 3. Store Results

Each completed scan stores:

- target value
- scan type
- status
- security score
- vulnerability counts by severity
- raw scan metadata
- individual vulnerability records

## 4. Display Dashboard Analytics

The dashboard API aggregates scan history for the logged-in user and returns:

- total scans
- total vulnerabilities
- average score
- severity distribution
- recent scans
- scan type distribution
- score trend
- daily vulnerability trend

## 5. Generate Reports

A completed scan can be turned into a PDF report or exported as JSON/CSV.

### Report endpoints

- `POST /api/reports/generate/{scan_id}`
- `GET /api/reports/download/{report_id}`
- `GET /api/reports/export/{scan_id}/json`
- `GET /api/reports/export/{scan_id}/csv`
- `GET /api/reports/`

## 6. Audit Logging

Important actions such as login, registration, scan completion, and report generation are stored in the audit log table for traceability.
