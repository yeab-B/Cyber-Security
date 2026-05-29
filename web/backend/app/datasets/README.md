# Security Datasets

This folder stores the analysis knowledge used by VulnAssess Pro.

## Files

- `security_headers.json` - required web security headers and analysis metadata
- `recommendations.json` - remediation knowledge base for vulnerability enrichment

## Why this exists

The scanner code reads these datasets at runtime so the knowledge base stays in one place and can later be replaced with a trained model or extended with more examples.

## Dataset fields

Each entry may include:

- `description`
- `impact`
- `remediation`
- `severity`
- `cwe_id`
- `ml_tags`
- `aliases`
- `analysis_hints`
- `confidence`
- `references`

These extra fields are intended to support dataset-driven analysis and future machine learning workflows.
