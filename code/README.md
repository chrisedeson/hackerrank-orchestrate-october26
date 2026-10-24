# Ghost Data Still Exists

Install the local media tools in a clean Debian/Ubuntu environment:

```bash
apt-get update && apt-get install -y poppler-utils tesseract-ocr
python3 code/main.py --dataset dataset --requests dataset/deletion_requests.csv --output output.csv
python3 code/evaluation/main.py output.csv
```

The runner uses only participant-facing `dataset/` inputs for inference. It resolves current and historical stable identity identifiers, normalizes record-scoped evidence, applies audit cutoffs and policy rules, then writes deterministic contract-ordered output. SQL evidence is processed only in a guarded in-memory SQLite workflow with restricted authorization; no organizer-only truth is used.

Media extraction is part of runtime: Poppler extracts PDF text and Tesseract 5.3.4 `eng` LSTM OCR handles PNG/image evidence where needed. Run evaluation against public samples with `python3 code/evaluation/main.py --sample sample_predictions.csv`; public golden sample output is evaluation-only and never inference input.
