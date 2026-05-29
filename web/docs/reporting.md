# Report Generation

VulnAssess Pro can generate downloadable reports from a completed scan.

## PDF Report Flow

1. The user opens a completed scan.
2. The backend loads the scan metadata and vulnerability list.
3. `ReportGenerator` builds a professional PDF using ReportLab.
4. The generated file is stored in the reports directory.
5. A `Report` database record is created.
6. The user can download the PDF from the reports page.

## What the PDF contains

- cover page
- executive summary
- risk score overview
- vulnerability summary table
- detailed findings
- remediation recommendations
- conclusion

## Export Formats

In addition to PDF, scan results can be exported as:

- JSON
- CSV

## Why this matters

These outputs make the tool useful for:

- security teams
- developers
- compliance reporting
- executive review
- remediation tracking

## Data Stored for Reports

Each report stores:

- scan id
- user id
- title
- format
- file path
- file size
- creation timestamp
