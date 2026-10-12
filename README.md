# Tenable CSV Merger

Merge any number of Tenable / Nessus CSV scan exports into a single CSV — entirely in your browser. No server, no install, no uploads: report data never leaves your machine.

## Usage

1. Download this repo (**Code → Download ZIP**) and unzip it, or `git clone` it.
2. Open `index.html` in a modern browser (Chrome or Edge recommended for very large merges).
3. Drop your CSV exports (or whole folders) onto the page, choose options, and click **Merge reports**.

Works offline and straight from disk (`file://`).

## Features

- **Handles large volumes** — files are streamed in 4 MB chunks inside a Web Worker, so multi-GB inputs and hundreds of reports don't freeze the page or exhaust memory.
- **Stream straight to disk** (Chrome/Edge) — output is written to the chosen file as it is produced. Other browsers get a regular download.
- **Different column layouts** — the output contains the union of all columns; reports missing a column get blank cells. Unwanted columns (e.g. `Plugin Output`) can be deselected.
- **De-duplication**
  - *Remove identical rows* (default)
  - *Remove repeated findings* — same Plugin ID + Host + Protocol + Port + CVE, keeping the first seen
  - *Keep everything*
- **Optional extras** — `Source File` column, exclude informational (Risk = None) findings, UTF-8 BOM for Excel.
- **Summary** — rows read/written, duplicates removed, unique hosts, severity breakdown, and a warning when the result exceeds Excel's 1,048,576-row limit.

## Files

| File | Purpose |
| --- | --- |
| `index.html` | Page markup |
| `styles.css` | Styling (light/dark) |
| `app.js` | UI: file handling, options, progress, results |
| `merge-worker.js` | Streaming CSV parser and merge engine (runs in a Web Worker) |
