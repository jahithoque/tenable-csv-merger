# Tenable Report Merger

Merge any number of Tenable / Nessus scan exports into a single Excel workbook or CSV — entirely in your browser. No server, no install, no uploads: report data never leaves your machine.

## Usage

1. Download this repo (**Code → Download ZIP**), extract it, or `git clone` it.
2. Open `index.html` in a current Chrome, Edge, Firefox or Safari (Chrome/Edge recommended for very large merges).
3. Drop your reports (or whole folders) onto the page, choose options, and click **Merge reports**.

Works offline and straight from disk (`file://`).

## Inputs

- **`.zip` archives** — e.g. the bulk downloads from Tenable. Every `.nessus` and `.csv` inside (including subfolders) is listed as its own report; nothing is extracted to disk.
- **`.nessus` files** (NessusClientData_v2 XML) — each finding becomes a row using the same column names as Tenable's CSV export (one row per CVE), plus host details such as IP address, FQDN, NetBIOS name, OS and scan name, and compliance fields (check name, result, actual / policy value, reference, audit file) for compliance scans.
- **Compliance results in CSV exports** — the check name and PASSED / FAILED / WARNING result are parsed from the Description into *Compliance Check* / *Compliance Result* columns.

### Report type

| Setting | Behaviour |
| --- | --- |
| **Auto-detect** (default) | Compliance results are recognised from `.nessus` compliance fields or a `[PASSED]` / `[FAILED]` marker in the Description; everything else is a vulnerability. |
| **Vulnerability scan** | Every row is a vulnerability finding, graded by Risk. |
| **Compliance audit** | Every row is a compliance check. When a report has no explicit result (common in Tenable exports), Risk is used: **None = Passed, High = Failed, Medium = Warning / Manual check** (Critical = Failed, Low = Warning). The check name comes from the Name column. |

The choice is remembered in your browser.

### Target identity

How rows are grouped into targets, for duplicate removal and every per-target count (Hosts/Targets sheet, top 10, pass rates, affected counts, authentication failures):

| Setting | Use when |
| --- | --- |
| **Host name** (default) | One scan target per host name. Duplicates are removed across all reports. |
| **Host + IP address** | Several machines report the same host name, e.g. Oracle RAC nodes. |
| **Host + report** | Each report scans a separate target, e.g. one Oracle database per scan even when several databases share a host or RAC. Duplicates are only removed within the same report, so identical results from two databases are both kept. |

With anything other than *Host name*, the Hosts sheet becomes **Targets** with Host, IP Address (and Report) columns. The choice is remembered in your browser.

### Authentication failures

Rows from the plugin IDs in **Authentication failures** (default `104410`, *Target Credential Status by Authentication Protocol - Failure for Provided Credentials*) are reported separately: a dashboard section with the number of affected hosts and a table of protocol / port / user / error parsed from the plugin output, an **Auth Failures** sheet, and an *Auth Failed* column on the Hosts sheet. They are never counted as compliance checks or vulnerabilities and, in the Excel workbook, appear only on the Auth Failures sheet, not in Findings (CSV output keeps them, as it has no separate sheet). An explicit exclusion rule still removes them entirely. Add more IDs (e.g. `21745`) comma-separated, or clear the field to turn this off.
- **`.csv` exports** from Nessus / Tenable.

Inputs can be mixed freely; the output contains the union of all columns.

## Output

- **Excel workbook (.xlsx)** (default), with these sheets:

  | Sheet | Contents |
  | --- | --- |
  | **Dashboard** | Overview, vulnerabilities by severity (with hosts affected), compliance results and **compliance score**, top 10 riskiest hosts, top 10 vulnerabilities, top 10 failed checks, plus a severity bar chart and compliance doughnut chart (native Excel charts) |
  | **Hosts / Targets** | Per host or target: IP / FQDN / OS, Critical–Info counts, Passed / Failed / Warning checks, pass rate, and a Status (Results / Auth failed / No usable results) |
  | **Vulnerabilities** | Per plugin: severity, hosts affected, occurrences, CVEs |
  | **Compliance** | Per check: Passed / Failed / Warning counts and pass rate (when compliance results exist) |
  | **No Results** | Targets that were scanned but returned only excluded or informational rows (e.g. only the SYN/TCP port scanners 11219 / 10335 or scan information 19506): plugins received, ports seen, reason. These rows never appear in Findings |
  | **Auth Failures** | Hosts where Tenable could not log in (plugin 104410 by default): IP, FQDN, OS, auth protocol, port, user, domain, error, full plugin output, source report |
  | **Sources** | Per report: rows read / written, which Findings sheet holds its rows, duplicates, exclusions, auth failures, errors |
  | **Findings** | The merged rows |

  Text cells keep Tenable's line breaks (wrapped, so words at line ends never run together). **Findings rows**: *Compact* shows the first two lines of each finding (full text in the formula bar or by expanding the row); *Fit full text* lets Excel size every row to its content.

  The summary sheets can be switched off. Findings have a bold, frozen header row with filters and numbers stored as numbers. Results larger than Excel's 1,048,576-row limit (or a single sheet's 4 GB size limit) continue on extra sheets named *Findings (2)*, *Findings (3)*, …; the Dashboard and Sources sheet say which sheet holds each report. Cells over Excel's 32,767-character limit are cut short and marked `[truncated]` (use CSV to keep full text).
- **CSV** — optional UTF-8 BOM for Excel.
- **Stream straight to disk** (Chrome/Edge) — output is written to the chosen file as it is produced. Other browsers get a regular download.

## Features

- **Handles large volumes** — files are streamed in chunks inside a Web Worker (one host at a time for `.nessus`), so multi-GB inputs and hundreds of reports don't freeze the page or exhaust memory.
- **De-duplication**
  - *Remove identical rows* (default)
  - *Remove repeated findings* — same Plugin ID + Host + Protocol + Port + CVE (+ compliance check name), keeping the first seen
  - *Keep everything*
- **Exclude findings by cell value** — add rules on any column, e.g. *Plugin ID is one of `19506, 10287, 11219-11220`*. Conditions: *is one of* (with numeric ranges), *is not one of* (keep only), *contains*, *matches regex*. Rows matching any rule are dropped, with per-rule counts in the summary. Rules are remembered in your browser.
- **Column selection** — click columns to remove them from the export, filter the list by name, or use a preset (*Tenable standard*, *Compliance*, *All*, *None*). Choices are remembered in your browser; compliance columns switch on automatically when reports contain compliance results.
- **Optional extras** — `Source File` column, exclude informational (Risk = None) vulnerability findings (compliance results, including PASSED checks, are always kept so the pass rate stays accurate).
- **Summary** — rows read/written, duplicates removed, unique hosts and a severity breakdown.

## Files

| File | Purpose |
| --- | --- |
| `index.html` | Page markup and styling (inlined so it works from local files on any OS) |
| `app.js` | UI: file handling, options, progress, results |
| `merge-worker.js` | Merge engine (runs in a Web Worker): ZIP reader, `.nessus` and CSV stream parsers, CSV and `.xlsx` writers |
