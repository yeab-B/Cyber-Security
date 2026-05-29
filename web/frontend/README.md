# VulnAssess Pro Frontend

This folder contains the static frontend for VulnAssess Pro.

## What it does

- shows the landing page and authentication modal
- switches between dark and light themes
- displays dashboard analytics after login
- launches web and APK scans
- shows generated reports and admin tools

## Main flow

1. The user opens the landing page.
2. The user signs in or registers.
3. The app stores the access token in local storage.
4. The dashboard loads user stats from the backend.
5. The user starts a scan or downloads a report.

## Backend integration

The frontend calls the FastAPI backend under `/api` for:

- authentication
- dashboard stats
- web scans
- APK scans
- reports

## Theme behavior

The interface uses a shared theme flag stored in local storage.

- `dark` mode uses darker surfaces and stronger contrast
- `light` mode uses softer panels and lighter navigation areas

## Documentation

For the full product documentation, read:

- [Documentation Index](../docs/README.md)
- [How It Works](../docs/how-it-works.md)
- [Vulnerability Analysis](../docs/vulnerability-analysis.md)
- [API Reference](../docs/api-reference.md)
- [Report Generation](../docs/reporting.md)
