# VulnAssess Pro Documentation

This folder contains the main product documentation for VulnAssess Pro.

## Documents

- [How It Works](how-it-works.md)
- [Vulnerability Analysis](vulnerability-analysis.md)
- [Analysis Model Type](model-type.md)
- [API Reference](api-reference.md)
- [Report Generation](reporting.md)

## Data Layer

- [Security Datasets](../backend/app/datasets/README.md)

## Quick Summary

VulnAssess Pro is a web and APK vulnerability assessment platform. A user signs in, runs a scan, the backend collects findings, enriches them with remediation guidance, calculates a security score, stores the results, and can generate downloadable PDF/JSON/CSV reports.

The scanner now reads its header rules and recommendation knowledge from dataset files, which makes the analysis layer easier to extend and later replace with a trained machine learning model.
