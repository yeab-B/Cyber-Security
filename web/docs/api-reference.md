# API Reference

Base path: `/api`

## Authentication
### `POST /auth/register`
Registers a new user and returns a bearer token.

### `POST /auth/login`
Authenticates a user and returns a bearer token.

### `GET /auth/me`
Returns the current authenticated user profile.

### `PUT /auth/me`
Updates the current user's profile.

### `POST /auth/change-password`
Changes the current user's password.

## Scanning
### `POST /scans/web`
Runs a passive web assessment.

Request body:
```json
{
  "url": "example.com",
  "scan_depth": "standard"
}
```

### `POST /scans/apk`
Uploads and analyzes an Android APK.

Form field:
- `file`: APK upload

### `GET /scans/`
Lists the current user's scans.

Query parameters:
- `skip`
- `limit`
- `scan_type`

### `GET /scans/{scan_id}`
Returns the full details for one scan.

### `DELETE /scans/{scan_id}`
Deletes a scan and its stored results.

## Dashboard
### `GET /dashboard/stats`
Returns aggregated statistics for the current user, including:
- total scans
- total vulnerabilities
- average score
- severity distribution
- recent scans
- score trend
- vulnerability trend
- scan type distribution

## Reports
### `POST /reports/generate/{scan_id}`
Generates a PDF report for a scan.

### `GET /reports/download/{report_id}`
Downloads a generated PDF report.

### `GET /reports/export/{scan_id}/json`
Exports scan results as JSON.

### `GET /reports/export/{scan_id}/csv`
Exports scan results as CSV.

### `GET /reports/`
Lists generated reports for the current user.

## Health
### `GET /health`
Returns a simple application health response.
