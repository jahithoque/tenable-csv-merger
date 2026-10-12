/* global mergeWorkerMain */
(() => {
  'use strict';

  const EXCEL_MAX_ROWS = 1048575; // 1,048,576 minus the header row
  const SEVERITY_ORDER = [
    ['critical', 'Critical', 'var(--sev-critical)'],
    ['high', 'High', 'var(--sev-high)'],
    ['medium', 'Medium', 'var(--sev-medium)'],
    ['low', 'Low', 'var(--sev-low)'],
    ['none', 'None / Info', 'var(--sev-none)'],
  ];
  const canSaveToDisk = typeof window.showSaveFilePicker === 'function';

  const $ = id => document.getElementById(id);
  const el = {
    dropzone: $('dropzone'),
    pickFiles: $('pick-files'), pickFolder: $('pick-folder'),
    filesCard: $('files-card'), fileCount: $('file-count'), fileRows: $('file-rows'), fileNotices: $('file-notices'),
    sortFiles: $('sort-files'), clearFiles: $('clear-files'),
    optionsCard: $('options-card'), optSource: $('opt-source'), optInfo: $('opt-info'), optBom: $('opt-bom'), optBomWrap: $('opt-bom-wrap'),
    optDisk: $('opt-disk'), optDiskWrap: $('opt-disk-wrap'), optName: $('opt-name'),
    colCount: $('col-count'), colNote: $('col-note'), colChips: $('col-chips'), colsAll: $('cols-all'), colsNone: $('cols-none'),
    mergeBtn: $('merge-btn'), mergeHint: $('merge-hint'),
    progressCard: $('progress-card'), progressTitle: $('progress-title'), progressBar: $('progress-bar'),
    progressFill: $('progress-fill'), progressPct: $('progress-pct'), progressDetail: $('progress-detail'),
    progressFile: $('progress-file'), cancelBtn: $('cancel-btn'),
    resultCard: $('result-card'), resultSaved: $('result-saved'), downloadBtn: $('download-btn'),
    stats: $('stats'), severity: $('severity'), resultNotices: $('result-notices'),
    ruleResults: $('rule-results'), rulesList: $('rules-list'), addRule: $('add-rule'), addPluginRule: $('add-plugin-rule'),
  };

  // Set initial visibility from script too, so a browser or viewer that drops
  // the HTML `hidden` attributes still starts with only the drop zone showing.
  for (const card of [el.filesCard, el.optionsCard, el.progressCard, el.resultCard, el.resultSaved, el.optDiskWrap]) {
    card.hidden = true;
  }

  const state = {
    entries: [],              // { id, file, status, headers, recognized, error, row, merged }
    nextId: 1,
    fingerprints: new Set(),  // name|size|lastModified, to skip re-added files
    excludedCols: new Set(),  // lower-cased column names the user turned off
    columns: [],              // [{ name, key, count }]
    merging: false,
    mergeWorker: null,
    resultUrl: null,
    rules: [],                // { id, column, op, text }
    nextRuleId: 1,
  };

  // The worker source lives in merge-worker.js as a plain function so it can
  // be loaded by a <script> tag and turned into a Blob URL here. This works
  // even when the page is opened from file://.
  const workerUrl = URL.createObjectURL(new Blob(
    ['(' + mergeWorkerMain.toString() + ')();'], { type: 'text/javascript' }));
  const createWorker = () => new Worker(workerUrl);

  // ---------------------------------------------------------------------
  // Formatting
  // ---------------------------------------------------------------------
  const nf = new Intl.NumberFormat();
  const fmtNum = n => nf.format(n);
  function fmtBytes(b) {
    if (b == null) return '—';
    const u = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return (i === 0 ? b : b.toFixed(b < 10 ? 2 : 1)) + ' ' + u[i];
  }
  function fmtDuration(ms) {
    const s = Math.round(ms / 1000);
    if (s < 60) return s + 's';
    const m = Math.floor(s / 60);
    return m < 60 ? `${m}m ${s % 60}s` : `${Math.floor(m / 60)}h ${m % 60}m`;
  }
  function notice(container, text) {
    const p = document.createElement('p');
    p.className = 'notice';
    p.textContent = text;
    container.appendChild(p);
  }

  // ---------------------------------------------------------------------
  // Adding files
  // ---------------------------------------------------------------------
  const scanWorker = createWorker();
  scanWorker.onmessage = e => {
    const m = e.data;
    if (m.type !== 'scanResult') return;
    const entry = state.entries.find(x => x.id === m.id);
    if (!entry) return; // removed while scanning
    if (m.children) { expandArchive(entry, m); return; }
    if (m.error) {
      entry.status = 'error';
      entry.error = m.error;
    } else {
      entry.status = 'ready';
      entry.headers = m.headers;
      entry.recognized = m.recognized;
    }
    renderRow(entry);
    scheduleRefresh();
  };

  // Replaces a scanned .zip row with one row per .nessus/.csv inside it.
  function expandArchive(zip, m) {
    let dup = 0;
    const kids = [];
    // Children carry their own fingerprints, so the archive's can go: a
    // re-added copy then expands again but its duplicate reports are skipped.
    state.fingerprints.delete(zip.fp);
    for (const c of m.children) {
      const fp = `${zip.fp}>${c.name}`;
      if (state.fingerprints.has(fp)) { dup++; continue; }
      state.fingerprints.add(fp);
      kids.push({
        id: state.nextId++, file: zip.file, zipEntry: c.entry, kind: c.kind,
        name: `${zip.name} › ${c.name}`, size: c.size, fp, merged: null,
        status: c.error ? 'error' : 'ready', error: c.error, headers: c.headers, recognized: c.recognized,
      });
    }
    const notes = [];
    if (m.nested) notes.push(`${fmtNum(m.nested)} nested archive${m.nested > 1 ? 's' : ''} skipped`);
    if (dup) notes.push(`${fmtNum(dup)} report${dup > 1 ? 's' : ''} already in the list`);
    if (notes.length) notice(el.fileNotices, `${zip.name}: ${notes.join('; ')}.`);

    if (!kids.length) {
      zip.status = 'error';
      zip.error = dup ? 'All reports inside are already in the list' : 'No .nessus or .csv files inside';
      renderRow(zip);
    } else {
      state.entries.splice(state.entries.indexOf(zip), 1, ...kids);
      const frag = document.createDocumentFragment();
      for (const kid of kids) frag.appendChild(buildRow(kid));
      zip.row.replaceWith(frag);
      renumber();
    }
    scheduleRefresh();
  }

  function addFiles(fileList) {
    if (state.merging) return;
    const fresh = [];
    let skippedType = 0, skippedDup = 0;
    for (const file of fileList) {
      const kind = (/\.(csv|nessus|zip)$/i.exec(file.name) || [])[1];
      if (!kind) { skippedType++; continue; }
      const name = file.webkitRelativePath || file.name;
      const fp = `${name}|${file.size}|${file.lastModified}`;
      if (state.fingerprints.has(fp)) { skippedDup++; continue; }
      state.fingerprints.add(fp);
      const entry = {
        id: state.nextId++, file, kind: kind.toLowerCase(), name, size: file.size, fp, status: 'scanning', merged: null,
      };
      state.entries.push(entry);
      fresh.push(entry);
    }

    el.fileNotices.textContent = '';
    if (skippedType) notice(el.fileNotices, `Skipped ${fmtNum(skippedType)} file${skippedType > 1 ? 's' : ''} that ${skippedType > 1 ? 'are' : 'is'} not .nessus, .csv or .zip.`);
    if (skippedDup) notice(el.fileNotices, `Skipped ${fmtNum(skippedDup)} file${skippedDup > 1 ? 's' : ''} already in the list.`);
    if (!fresh.length) { scheduleRefresh(); return; }

    const frag = document.createDocumentFragment();
    for (const entry of fresh) frag.appendChild(buildRow(entry));
    el.fileRows.appendChild(frag);
    renumber();
    scanWorker.postMessage({ type: 'scan', files: fresh.map(x => ({ id: x.id, file: x.file })) });
    clearResult();
    scheduleRefresh();
  }

  // Recursively collect files from dropped folders.
  async function filesFromDataTransfer(dt) {
    const items = [...(dt.items || [])].filter(i => i.kind === 'file');
    const entries = items.map(i => (i.webkitGetAsEntry ? i.webkitGetAsEntry() : null));
    if (!entries.length || entries.some(x => !x)) return [...dt.files];

    const out = [];
    const readAll = dir => new Promise((resolve, reject) => {
      const reader = dir.createReader();
      const acc = [];
      const next = () => reader.readEntries(batch => {
        if (!batch.length) resolve(acc);
        else { acc.push(...batch); next(); }
      }, reject);
      next();
    });
    const walk = async entry => {
      if (entry.isFile) {
        out.push(await new Promise((res, rej) => entry.file(res, rej)));
      } else if (entry.isDirectory) {
        for (const child of await readAll(entry)) await walk(child);
      }
    };
    for (const entry of entries) await walk(entry);
    return out;
  }

  // The file inputs are created on demand and never attached to the page, so
  // the native "Browse… / No file selected" controls can't leak into the layout.
  function openPicker(folder) {
    if (state.merging) return;
    const input = document.createElement('input');
    input.type = 'file';
    input.multiple = true;
    if (folder) input.webkitdirectory = true;
    else input.accept = '.nessus,.csv,.zip,text/csv,application/zip';
    input.addEventListener('change', () => addFiles([...input.files]));
    input.click();
  }
  el.pickFiles.addEventListener('click', e => { e.stopPropagation(); openPicker(false); });
  el.pickFolder.addEventListener('click', e => { e.stopPropagation(); openPicker(true); });
  el.dropzone.addEventListener('click', () => openPicker(false));
  el.dropzone.addEventListener('keydown', e => {
    if (e.target === el.dropzone && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); openPicker(false); }
  });

  let dragDepth = 0;
  document.addEventListener('dragenter', e => { e.preventDefault(); dragDepth++; el.dropzone.classList.add('over'); });
  document.addEventListener('dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; el.dropzone.classList.remove('over'); } });
  document.addEventListener('dragover', e => e.preventDefault());
  document.addEventListener('drop', async e => {
    e.preventDefault();
    dragDepth = 0;
    el.dropzone.classList.remove('over');
    if (state.merging) return;
    try {
      addFiles(await filesFromDataTransfer(e.dataTransfer));
    } catch (err) {
      el.fileNotices.textContent = '';
      notice(el.fileNotices, 'Could not read the dropped items: ' + err.message);
    }
  });

  // ---------------------------------------------------------------------
  // File table
  // ---------------------------------------------------------------------
  function buildRow(entry) {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td class="num idx"></td><td class="name"></td><td class="num size"></td>' +
      '<td class="num cols"></td><td class="st"></td><td class="num merged"></td>' +
      '<td><button type="button" class="remove" aria-label="Remove">×</button></td>';
    tr.querySelector('.name').textContent = entry.name;
    tr.querySelector('.name').title = entry.name;
    tr.querySelector('.size').textContent = fmtBytes(entry.size);
    tr.querySelector('.remove').addEventListener('click', () => removeEntry(entry));
    entry.row = tr;
    renderRow(entry);
    return tr;
  }

  function renderRow(entry) {
    const tr = entry.row;
    if (!tr) return;
    const st = tr.querySelector('.st');
    let cls = '', text = '';
    if (entry.status === 'scanning') text = entry.kind === 'zip' ? 'Opening archive…' : 'Reading header…';
    else if (entry.status === 'error') { cls = 'err'; text = entry.error; }
    else if (entry.mergeError) { cls = 'err'; text = 'Failed: ' + entry.mergeError; }
    else if (!entry.recognized) { cls = 'warn'; text = 'No Plugin ID / Host column'; }
    else { cls = 'ok'; text = 'Ready'; }
    st.innerHTML = '';
    const span = document.createElement('span');
    span.className = 'status ' + cls;
    span.textContent = text;
    span.title = text;
    st.appendChild(span);
    tr.querySelector('.cols').textContent = entry.headers ? fmtNum(entry.headers.length) : '';
    tr.querySelector('.merged').textContent = entry.merged == null ? '' : fmtNum(entry.merged);
  }

  function renumber() {
    state.entries.forEach((entry, i) => { entry.row.querySelector('.idx').textContent = i + 1; });
  }

  function removeEntry(entry) {
    if (state.merging) return;
    state.entries = state.entries.filter(x => x !== entry);
    state.fingerprints.delete(entry.fp);
    entry.row.remove();
    renumber();
    clearResult();
    scheduleRefresh();
  }

  el.clearFiles.addEventListener('click', () => {
    if (state.merging) return;
    state.entries = [];
    state.fingerprints.clear();
    el.fileRows.textContent = '';
    el.fileNotices.textContent = '';
    clearResult();
    scheduleRefresh();
  });

  el.sortFiles.addEventListener('click', () => {
    if (state.merging) return;
    const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });
    const name = x => x.name;
    state.entries.sort((a, b) => collator.compare(name(a), name(b)));
    const frag = document.createDocumentFragment();
    for (const entry of state.entries) frag.appendChild(entry.row);
    el.fileRows.appendChild(frag);
    renumber();
    clearResult();
  });

  // ---------------------------------------------------------------------
  // Columns + summary (batched to one update per frame while scanning)
  // ---------------------------------------------------------------------
  let refreshQueued = false;
  function scheduleRefresh() {
    if (refreshQueued) return;
    refreshQueued = true;
    requestAnimationFrame(() => { refreshQueued = false; refresh(); });
  }

  function computeColumns() {
    const map = new Map();
    for (const entry of state.entries) {
      if (entry.status !== 'ready') continue;
      for (const h of entry.headers) {
        if (!h) continue;
        const key = h.toLowerCase();
        if (key === 'source file') continue; // we add our own
        const col = map.get(key);
        if (col) col.count++;
        else map.set(key, { name: h, key, count: 1 });
      }
    }
    return [...map.values()];
  }

  function renderColumns() {
    const ready = state.entries.filter(x => x.status === 'ready').length;
    el.colChips.textContent = '';
    const frag = document.createDocumentFragment();
    let partial = 0;
    for (const col of state.columns) {
      const b = document.createElement('button');
      b.type = 'button';
      const isPartial = col.count < ready;
      if (isPartial) partial++;
      b.className = 'chip' + (state.excludedCols.has(col.key) ? '' : ' on') + (isPartial ? ' partial' : '');
      b.textContent = col.name;
      b.title = isPartial ? `Present in ${col.count} of ${ready} reports` : 'Present in every report';
      b.setAttribute('aria-pressed', String(!state.excludedCols.has(col.key)));
      b.addEventListener('click', () => {
        if (state.excludedCols.has(col.key)) state.excludedCols.delete(col.key);
        else state.excludedCols.add(col.key);
        clearResult();
        refresh();
      });
      frag.appendChild(b);
    }
    el.colChips.appendChild(frag);
    const included = state.columns.filter(c => !state.excludedCols.has(c.key)).length;
    el.colCount.textContent = `${included} of ${state.columns.length} selected`;
    el.colNote.textContent = partial
      ? `${partial} column${partial > 1 ? 's' : ''} missing from some reports`
      : (state.columns.length ? 'All reports share the same columns' : '');
  }

  function refresh() {
    const n = state.entries.length;
    el.filesCard.hidden = n === 0;
    el.optionsCard.hidden = n === 0;
    const totalSize = state.entries.reduce((s, x) => s + x.size, 0);
    el.fileCount.textContent = n ? `${fmtNum(n)} · ${fmtBytes(totalSize)}` : '';

    const before = state.columns.map(c => c.name).join('\u0000');
    state.columns = computeColumns();
    renderColumns();
    // Rebuild rule dropdowns only when the column list changed.
    if (state.columns.map(c => c.name).join('\u0000') !== before) renderRules();
    else updateRuleStatus();

    for (const b of [el.sortFiles, el.clearFiles, el.pickFiles, el.pickFolder, el.addRule, el.addPluginRule]) b.disabled = state.merging;
    for (const entry of state.entries) entry.row.querySelector('.remove').disabled = state.merging;
  }

  function refreshMergeButton() {
    const n = state.entries.length;
    const scanning = state.entries.filter(x => x.status === 'scanning').length;
    const ready = state.entries.filter(x => x.status === 'ready');
    const errors = state.entries.filter(x => x.status === 'error').length;
    const included = state.columns.filter(c => !state.excludedCols.has(c.key)).length;

    const badRules = state.rules.filter(ruleError).length;
    el.mergeBtn.disabled = state.merging || scanning > 0 || ready.length === 0 || included === 0 || badRules > 0;
    const parts = [];
    if (scanning) parts.push(`Reading headers… ${fmtNum(n - scanning)} / ${fmtNum(n)}`);
    else if (ready.length) parts.push(`${fmtNum(ready.length)} report${ready.length > 1 ? 's' : ''} ready (${fmtBytes(ready.reduce((s, x) => s + x.size, 0))})`);
    if (errors) parts.push(`${fmtNum(errors)} unreadable, will be skipped`);
    if (!included && state.columns.length) parts.push('select at least one column');
    if (badRules) parts.push('fix the invalid exclusion rule');
    const rules = activeRules().length;
    if (rules && !badRules) parts.push(`${rules} exclusion rule${rules > 1 ? 's' : ''} active`);
    el.mergeHint.textContent = parts.join(' · ');
  }

  el.colsAll.addEventListener('click', () => { state.excludedCols.clear(); clearResult(); refresh(); });
  el.colsNone.addEventListener('click', () => {
    for (const c of state.columns) state.excludedCols.add(c.key);
    clearResult();
    refresh();
  });

  // ---------------------------------------------------------------------
  // Exclusion rules
  // ---------------------------------------------------------------------
  const RULE_OPS = [
    ['in', 'is one of', 'e.g. 19506, 10287, 11219 or a range like 10000-10500'],
    ['notin', 'is not one of', 'Keeps only these values, e.g. Critical, High'],
    ['contains', 'contains', 'One phrase per line, e.g. SSL Certificate'],
    ['regex', 'matches regex', 'One pattern per line, e.g. ^CVE-2019-'],
  ];
  const RULES_STORAGE_KEY = 'tenable-merger.rules.v1';

  function ruleValues(rule) {
    // Lists split on commas or new lines; free text splits on new lines only.
    const parts = rule.op === 'in' || rule.op === 'notin' ? rule.text.split(/[,\n]/) : rule.text.split('\n');
    return parts.map(v => v.trim()).filter(Boolean);
  }

  function ruleError(rule) {
    if (rule.op !== 'regex') return null;
    for (const v of ruleValues(rule)) {
      try { new RegExp(v, 'i'); } catch (err) { return `Invalid pattern “${v}”`; }
    }
    return null;
  }

  // Rules with no values are ignored rather than blocking the merge.
  const activeRules = () => state.rules.filter(r => r.column && ruleValues(r).length);

  function saveRules() {
    try {
      localStorage.setItem(RULES_STORAGE_KEY,
        JSON.stringify(state.rules.map(({ column, op, text }) => ({ column, op, text }))));
    } catch (_) { /* storage unavailable (private mode, file:// restrictions) */ }
  }

  function loadRules() {
    try {
      const saved = JSON.parse(localStorage.getItem(RULES_STORAGE_KEY) || '[]');
      for (const r of saved) {
        if (r && typeof r.column === 'string' && RULE_OPS.some(o => o[0] === r.op)) {
          state.rules.push({ id: state.nextRuleId++, column: r.column, op: r.op, text: String(r.text || '') });
        }
      }
    } catch (_) { /* ignore corrupt or unavailable storage */ }
  }

  function addRule(column, op = 'in') {
    const fallback = state.columns.find(c => c.key === 'plugin id') || state.columns[0];
    state.rules.push({ id: state.nextRuleId++, column: column || (fallback ? fallback.name : 'Plugin ID'), op, text: '' });
    saveRules();
    renderRules();
    clearResult();
    refresh();
    const areas = el.rulesList.querySelectorAll('textarea');
    if (areas.length) areas[areas.length - 1].focus();
  }

  function renderRules() {
    el.rulesList.textContent = '';
    const colNames = state.columns.map(c => c.name);
    for (const rule of state.rules) {
      const row = document.createElement('div');
      row.className = 'rule';

      const colSel = document.createElement('select');
      colSel.setAttribute('aria-label', 'Column');
      const names = colNames.some(n => n.toLowerCase() === rule.column.toLowerCase()) ? colNames : [rule.column, ...colNames];
      for (const name of names) colSel.add(new Option(name, name, false, name.toLowerCase() === rule.column.toLowerCase()));
      colSel.addEventListener('change', () => { rule.column = colSel.value; saveRules(); clearResult(); updateRuleStatus(); });

      const opSel = document.createElement('select');
      opSel.setAttribute('aria-label', 'Condition');
      for (const [value, label] of RULE_OPS) opSel.add(new Option(label, value, false, value === rule.op));

      const area = document.createElement('textarea');
      area.rows = 2;
      area.spellcheck = false;
      area.value = rule.text;
      area.setAttribute('aria-label', 'Values');

      const meta = document.createElement('div');
      meta.className = 'rule-meta';

      const setPlaceholder = () => { area.placeholder = RULE_OPS.find(o => o[0] === rule.op)[2]; };
      setPlaceholder();
      opSel.addEventListener('change', () => { rule.op = opSel.value; setPlaceholder(); saveRules(); clearResult(); updateRuleStatus(); });
      area.addEventListener('input', () => { rule.text = area.value; saveRules(); clearResult(); updateRuleStatus(); });

      const del = document.createElement('button');
      del.type = 'button';
      del.className = 'remove';
      del.textContent = '×';
      del.setAttribute('aria-label', 'Remove rule');
      del.addEventListener('click', () => {
        state.rules = state.rules.filter(r => r !== rule);
        saveRules();
        renderRules();
        clearResult();
        refresh();
      });

      const fields = document.createElement('div');
      fields.className = 'rule-fields';
      fields.append(colSel, opSel, area, del);
      row.append(fields, meta);
      rule.metaEl = meta;
      el.rulesList.appendChild(row);
    }
    updateRuleStatus();
  }

  // Updates per-rule hints and the merge button without rebuilding inputs
  // (which would steal focus while typing).
  function updateRuleStatus() {
    const ready = state.entries.filter(x => x.status === 'ready');
    for (const rule of state.rules) {
      if (!rule.metaEl) continue;
      const err = ruleError(rule);
      const n = ruleValues(rule).length;
      const key = rule.column.toLowerCase();
      const missing = ready.filter(x => !x.headers.some(h => h.toLowerCase() === key)).length;
      rule.metaEl.className = 'rule-meta' + (err ? ' err' : '');
      let text = err || (n ? `${n} value${n > 1 ? 's' : ''}` : 'No values yet; this rule is ignored');
      if (!err && missing && ready.length) {
        text += ` · column not in ${missing} of ${ready.length} report${ready.length > 1 ? 's' : ''} (rule skipped there)`;
      }
      rule.metaEl.textContent = text;
    }
    refreshMergeButton();
  }

  el.addRule.addEventListener('click', () => addRule());
  el.addPluginRule.addEventListener('click', () => {
    const col = state.columns.find(c => c.key === 'plugin id' || c.key === 'plugin');
    addRule(col ? col.name : 'Plugin ID', 'in');
  });

  // ---------------------------------------------------------------------
  // Merge
  // ---------------------------------------------------------------------
  if (canSaveToDisk) el.optDiskWrap.hidden = false;

  const FORMATS = {
    xlsx: { ext: '.xlsx', description: 'Excel workbook', mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' },
    csv: { ext: '.csv', description: 'CSV file', mime: 'text/csv' },
  };
  const outputFormat = () => document.querySelector('input[name="format"]:checked').value;

  function outputName() {
    const { ext } = FORMATS[outputFormat()];
    let name = el.optName.value.trim().replace(/[\\/:*?"<>|]+/g, '_') || 'merged_tenable_report';
    name = name.replace(/\.(csv|xlsx)$/i, '');
    return name + ext;
  }

  function syncFormat() {
    el.optBomWrap.hidden = outputFormat() !== 'csv';
    el.optName.value = outputName();
    clearResult();
  }
  for (const r of document.querySelectorAll('input[name="format"]')) r.addEventListener('change', syncFormat);
  syncFormat();

  async function startMerge() {
    const entries = state.entries.filter(x => x.status === 'ready');
    const columns = state.columns.filter(c => !state.excludedCols.has(c.key)).map(c => c.name);
    if (!entries.length || !columns.length) return;

    // Must run first, while we still hold the click's user activation.
    let handle = null;
    if (canSaveToDisk && el.optDisk.checked) {
      try {
        handle = await window.showSaveFilePicker({
          suggestedName: outputName(),
          types: [{ description: FORMATS[outputFormat()].description, accept: { [FORMATS[outputFormat()].mime]: [FORMATS[outputFormat()].ext] } }],
        });
      } catch (err) {
        if (err.name === 'AbortError') return;
        handle = null; // picker unavailable here (e.g. sandboxed frame), use download instead
      }
    }

    clearResult();
    state.merging = true;
    for (const entry of state.entries) { entry.merged = null; entry.mergeError = null; renderRow(entry); }
    refresh();

    el.progressCard.hidden = false;
    el.progressTitle.textContent = 'Merging…';
    el.cancelBtn.disabled = false;
    setProgress(0, 0, entries[0], 0, Date.now());
    el.progressCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    const sentRules = activeRules().map(r => ({ column: r.column, op: r.op, n: ruleValues(r).length }));
    const startedAt = Date.now();
    const totalBytes = entries.reduce((s, x) => s + (x.zipEntry ? x.zipEntry.compSize : x.file.size), 0);
    const worker = createWorker();
    state.mergeWorker = worker;
    let activeRow = null;

    const finish = () => {
      worker.terminate();
      state.mergeWorker = null;
      state.merging = false;
      if (activeRow) activeRow.classList.remove('active');
      refresh();
    };

    worker.onmessage = async e => {
      const m = e.data;
      if (m.type === 'progress') {
        const entry = entries[m.fileIndex];
        if (activeRow !== entry.row) {
          if (activeRow) activeRow.classList.remove('active');
          activeRow = entry.row;
          activeRow.classList.add('active');
        }
        setProgress(m.bytesDone / (m.totalBytes || 1), m.bytesDone, entry, m.rowsOut, startedAt, m.totalBytes);
      } else if (m.type === 'fileDone') {
        const entry = entries[m.fileIndex];
        entry.merged = m.stats.rowsOut;
        entry.mergeError = m.stats.error;
        renderRow(entry);
        const next = entries[m.fileIndex + 1];
        if (next) el.progressFile.textContent = next.name;
      } else if (m.type === 'done') {
        setProgress(1, totalBytes, null, m.stats.rowsOut, startedAt, totalBytes);
        el.progressTitle.textContent = 'Finishing…';
        el.cancelBtn.disabled = true;
        let savedTo = null;
        try {
          if (handle) {
            if (m.blob) { // worker couldn't write directly; do it from here
              const w = await handle.createWritable();
              await w.write(m.blob);
              await w.close();
            }
            savedTo = handle.name;
            if (m.stats.bytesOut == null) m.stats.bytesOut = (await handle.getFile()).size;
          }
        } catch (err) {
          savedTo = null;
          notice(el.resultNotices, `Could not write to the chosen file (${err.message}). Use the download button instead.`);
        }
        finish();
        el.progressCard.hidden = true;
        showResult(m.stats, m.blob, savedTo, entries, Date.now() - startedAt, sentRules);
      } else if (m.type === 'cancelled') {
        finish();
        el.progressCard.hidden = true;
      } else if (m.type === 'error') {
        finish();
        el.progressTitle.textContent = 'Merge failed';
        el.progressDetail.textContent = m.message;
        el.cancelBtn.disabled = true;
      }
    };
    worker.onerror = e => {
      finish();
      el.progressTitle.textContent = 'Merge failed';
      el.progressDetail.textContent = e.message || 'The merge worker crashed (possibly out of memory).';
      el.cancelBtn.disabled = true;
    };

    worker.postMessage({
      type: 'merge',
      sources: entries.map(x => ({ file: x.file, entry: x.zipEntry || null, kind: x.kind, name: x.name })),
      columns,
      outputHandle: handle,
      options: {
        dedupe: document.querySelector('input[name="dedupe"]:checked').value,
        addSource: el.optSource.checked,
        excludeInfo: el.optInfo.checked,
        format: outputFormat(),
        bom: el.optBom.checked,
        rules: activeRules().map(r => ({ column: r.column, op: r.op, values: ruleValues(r) })),
      },
    });
  }

  function setProgress(frac, bytesDone, entry, rows, startedAt, totalBytes) {
    const pct = Math.min(100, Math.floor(frac * 1000) / 10);
    el.progressFill.style.width = pct + '%';
    el.progressBar.setAttribute('aria-valuenow', String(Math.round(pct)));
    el.progressPct.textContent = pct.toFixed(1) + '%';
    const elapsed = Date.now() - startedAt;
    const parts = [`${fmtNum(rows)} rows written`];
    if (totalBytes) parts.push(`${fmtBytes(bytesDone)} of ${fmtBytes(totalBytes)}`);
    if (elapsed > 1500 && frac > 0.01 && frac < 1) {
      parts.push(`${fmtBytes(bytesDone / (elapsed / 1000))}/s`);
      parts.push(`~${fmtDuration(elapsed / frac - elapsed)} left`);
    }
    el.progressDetail.textContent = parts.join(' · ');
    if (entry) el.progressFile.textContent = entry.name;
  }

  el.mergeBtn.addEventListener('click', startMerge);
  el.cancelBtn.addEventListener('click', () => {
    const worker = state.mergeWorker;
    if (!worker) return;
    el.cancelBtn.disabled = true;
    el.progressTitle.textContent = 'Cancelling…';
    worker.postMessage({ type: 'cancel' });
    // If the worker is stuck mid-chunk, don't wait forever.
    setTimeout(() => {
      if (state.mergeWorker === worker) {
        worker.terminate();
        state.mergeWorker = null;
        state.merging = false;
        el.progressCard.hidden = true;
        refresh();
      }
    }, 5000);
  });

  // ---------------------------------------------------------------------
  // Results
  // ---------------------------------------------------------------------
  function clearResult() {
    if (state.resultUrl) URL.revokeObjectURL(state.resultUrl);
    state.resultUrl = null;
    el.resultCard.hidden = true;
    el.resultNotices.textContent = '';
  }

  function showResult(stats, blob, savedTo, entries, elapsed, rules) {
    el.resultCard.hidden = false;
    const name = outputName();
    if (blob) state.resultUrl = URL.createObjectURL(blob);
    el.downloadBtn.hidden = !blob;
    el.resultSaved.hidden = !savedTo;
    el.resultSaved.textContent = savedTo ? `Saved to ${savedTo}` : '';

    const cards = [
      [fmtNum(entries.length), 'Reports merged'],
      [fmtNum(stats.rowsIn), 'Rows read'],
      [fmtNum(stats.rowsOut), 'Rows written'],
      [fmtNum(stats.duplicates), 'Duplicates removed'],
      [fmtNum(stats.filtered), 'Info rows excluded'],
      [fmtNum(stats.excluded), 'Removed by rules'],
      [fmtNum(stats.uniqueHosts), 'Unique hosts'],
      [fmtNum(stats.columns), 'Columns'],
      [fmtBytes(stats.bytesOut), 'Output size'],
      [fmtDuration(elapsed), 'Time taken'],
    ];
    el.stats.innerHTML = '';
    for (const [v, k] of cards) {
      const d = document.createElement('div');
      d.className = 'stat';
      d.innerHTML = '<div class="v"></div><div class="k"></div>';
      d.querySelector('.v').textContent = v;
      d.querySelector('.k').textContent = k;
      el.stats.appendChild(d);
    }

    renderSeverity(stats.severity);

    el.ruleResults.textContent = '';
    if (rules.length) {
      const opLabel = op => RULE_OPS.find(o => o[0] === op)[1];
      const h = document.createElement('h3');
      h.textContent = 'Exclusion rules';
      const ul = document.createElement('ul');
      rules.forEach((r, i) => {
        const li = document.createElement('li');
        li.textContent = `${r.column} ${opLabel(r.op)} ${r.n} value${r.n > 1 ? 's' : ''}: removed ${fmtNum(stats.ruleHits[i])} row${stats.ruleHits[i] === 1 ? '' : 's'}`;
        ul.appendChild(li);
      });
      el.ruleResults.append(h, ul);
    }

    if (stats.format === 'xlsx' && stats.sheets > 1) {
      notice(el.resultNotices, `${fmtNum(stats.rowsOut)} rows is more than one Excel sheet can hold, so the workbook has ${stats.sheets} sheets ("Findings", "Findings (2)", …), each with its own header row.`);
    }
    if (stats.truncatedCells) {
      notice(el.resultNotices, `${fmtNum(stats.truncatedCells)} cell${stats.truncatedCells > 1 ? 's were' : ' was'} longer than Excel's 32,767-character limit and ${stats.truncatedCells > 1 ? 'were' : 'was'} cut short (marked "[truncated]"). Choose CSV output to keep the full text.`);
    }
    if (stats.format === 'csv' && stats.rowsOut > EXCEL_MAX_ROWS) {
      notice(el.resultNotices, `The merged file has ${fmtNum(stats.rowsOut)} rows. Excel can only open the first ${fmtNum(EXCEL_MAX_ROWS)}. Choose Excel output to split it across sheets, or exclude informational findings.`);
    }
    if (stats.malformed) {
      notice(el.resultNotices, `${fmtNum(stats.malformed)} row${stats.malformed > 1 ? 's' : ''} had a different number of fields than their header. They were kept, with values mapped by position.`);
    }
    const failed = stats.perFile.map((s, i) => [s, entries[i]]).filter(([s]) => s.error);
    for (const [s, entry] of failed) notice(el.resultNotices, `${entry.name}: ${s.error}`);
    const unrecognized = entries.filter(x => !x.recognized).length;
    if (unrecognized) {
      notice(el.resultNotices, `${fmtNum(unrecognized)} report${unrecognized > 1 ? 's have' : ' has'} no Plugin ID / Host column, so ${unrecognized > 1 ? 'they may not be' : 'it may not be'} Tenable exports. Merged anyway; duplicate checks fall back to identical-row matching.`);
    }

    el.resultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    if (blob && !savedTo) triggerDownload();
  }

  function renderSeverity(severity) {
    el.severity.textContent = '';
    const counts = new Map();
    for (const [label, n] of Object.entries(severity)) {
      const key = label.toLowerCase();
      const norm = key === 'info' || key === 'informational' ? 'none' : key;
      counts.set(norm, (counts.get(norm) || 0) + n);
    }
    const total = [...counts.values()].reduce((a, b) => a + b, 0);
    if (!total) return;

    const known = new Set(SEVERITY_ORDER.map(s => s[0]));
    const items = SEVERITY_ORDER.filter(([k]) => counts.get(k)).map(([k, label, color]) => [label, counts.get(k), color]);
    const other = [...counts].filter(([k]) => !known.has(k)).reduce((s, [, n]) => s + n, 0);
    if (other) items.push(['Other', other, 'var(--muted)']);

    const bar = document.createElement('div');
    bar.className = 'sev-bar';
    const legend = document.createElement('div');
    legend.className = 'sev-legend';
    for (const [label, n, color] of items) {
      const seg = document.createElement('span');
      seg.style.width = (n / total * 100) + '%';
      seg.style.background = color;
      seg.title = `${label}: ${fmtNum(n)}`;
      bar.appendChild(seg);
      const l = document.createElement('span');
      l.innerHTML = '<i></i><b></b>';
      l.querySelector('i').style.background = color;
      l.querySelector('b').textContent = `${label} ${fmtNum(n)}`;
      l.querySelector('b').style.fontWeight = '500';
      legend.appendChild(l);
    }
    el.severity.append(bar, legend);
  }

  function triggerDownload() {
    if (!state.resultUrl) return;
    const a = document.createElement('a');
    a.href = state.resultUrl;
    a.download = outputName();
    document.body.appendChild(a);
    a.click();
    a.remove();
  }
  el.downloadBtn.addEventListener('click', triggerDownload);

  window.addEventListener('beforeunload', e => {
    if (state.merging) { e.preventDefault(); e.returnValue = ''; }
  });

  loadRules();
  renderRules();
  refresh();
})();
