# Tenable Report Merger

Merge any number of Tenable / Nessus scan exports into a single Excel workbook or CSV — entirely in your browser. No server, no install, no uploads: report data never leaves your machine.

## Usage

1. Download this repo (**Code → Download ZIP**), extract it, or `git clone` it.
2. Open `index.html` in a current Chrome, Edge, Firefox or Safari (Chrome/Edge recommended for very large merges).
3. Drop your reports (or whole folders) onto the page, choose options, and click **Merge reports**.

Works offline and straight from disk (`file://`).

## Inputs

- **`.zip` archives** — e.g. the bulk downloads from Tenable. Every `.nessus` and `.csv` inside (including subfolders) is listed as its own report; nothing is extracted to disk.
- **`.nessus` files** (NessusClientData_v2 XML) — each finding becomes a row using the same column names as Tenable's CSV export (one row per CVE), plus host details such as IP address, FQDN, NetBIOS name, OS and scan name.
- **`.csv` exports** from Nessus / Tenable.

Inputs can be mixed freely; the output contains the union of all columns.

## Output

- **Excel workbook (.xlsx)** (default) — bold, frozen header row with filters, numbers stored as numbers. Results larger than Excel's 1,048,576-row limit continue on extra sheets. Cells over Excel's 32,767-character limit are cut short and marked `[truncated]` (use CSV to keep full text).
- **CSV** — optional UTF-8 BOM for Excel.
- **Stream straight to disk** (Chrome/Edge) — output is written to the chosen file as it is produced. Other browsers get a regular download.

## Features

- **Handles large volumes** — files are streamed in chunks inside a Web Worker (one host at a time for `.nessus`), so multi-GB inputs and hundreds of reports don't freeze the page or exhaust memory.
- **De-duplication**
  - *Remove identical rows* (default)
  - *Remove repeated findings* — same Plugin ID + Host + Protocol + Port + CVE, keeping the first seen
  - *Keep everything*
- **Exclude findings by cell value** — add rules on any column, e.g. *Plugin ID is one of `19506, 10287, 11219-11220`*. Conditions: *is one of* (with numeric ranges), *is not one of* (keep only), *contains*, *matches regex*. Rows matching any rule are dropped, with per-rule counts in the summary. Rules are remembered in your browser.
- **Column selection** — drop columns you don't need (e.g. `Plugin Output`) to shrink the file.
- **Optional extras** — `Source File` column, exclude informational (Risk = None) findings.
- **Summary** — rows read/written, duplicates removed, unique hosts and a severity breakdown.

## Files

| File | Purpose |
| --- | --- |
| `index.html` | Page markup and styling (inlined so it works from local files on any OS) |
| `app.js` | UI: file handling, options, progress, results |
| `merge-worker.js` | Merge engine (runs in a Web Worker): ZIP reader, `.nessus` and CSV stream parsers, CSV and `.xlsx` writers |
