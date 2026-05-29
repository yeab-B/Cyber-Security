# Analysis Model Type

VulnAssess Pro currently uses a dataset-driven similarity model for vulnerability analysis.

## Model Type

This is a lightweight, rule-guided lexical similarity ranker. It is not a trained deep learning model yet. Instead, it compares a vulnerability record against the dataset using:

- keyword overlap
- alias matching
- metadata hint matching
- confidence values stored in the dataset

## How It Works

1. The scanner produces a vulnerability record.
2. The recommendation engine sends the record to the analysis model.
3. The model compares the vulnerability text with the dataset entries.
4. The best matching dataset entry is selected.
5. The selected dataset item provides:
   - risk explanation
   - business impact
   - technical impact
   - remediation steps
   - metadata such as CWE IDs, tags, and references

## Dataset Signals Used

Each dataset entry can include:

- `aliases`
- `ml_tags`
- `analysis_hints`
- `cwe_ids`
- `references`
- `confidence`

These fields help the model score matches more accurately.

## Why This Approach Was Chosen

- easy to maintain
- easy to expand with new dataset rows
- no external ML dependency required
- deterministic and explainable
- suitable for security workflows where traceability matters

## Current Output

The model returns:

- `matched_dataset_key`
- `analysis_confidence`
- `ml_tags`
- `cwe_ids`
- `references`
- enriched remediation and impact text

## Future Upgrade Path

This dataset-driven model can later be replaced with a real machine learning classifier or embedding-based retrieval model while keeping the same input and output structure.

## Short Summary

Right now, VulnAssess Pro uses a hybrid dataset-based similarity model, not a trained ML model. The dataset is the source of truth for the analysis knowledge base.
