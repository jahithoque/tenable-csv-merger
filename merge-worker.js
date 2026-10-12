/*
 * Merge engine. Everything lives inside mergeWorkerMain so app.js can
 * serialise it into a Blob-URL worker — that keeps the app working when
 * index.html is opened straight from disk (file://), where
 * `new Worker('merge-worker.js')` would be blocked.
 */
function mergeWorkerMain() {
  'use strict';

  const READ_CHUNK = 4 * 1024 * 1024;        // bytes per file read
  const FLUSH_CHARS = 4 * 1024 * 1024;       // chars buffered before a write
  const BLOB_PART_CHARS = 32 * 1024 * 1024;  // chars folded into one Blob part
  const PROGRESS_INTERVAL_MS = 150;

  // ---------------------------------------------------------------------
  // Streaming RFC-4180 CSV parser. Handles quoted fields containing commas,
  // quotes and newlines, even when they straddle chunk boundaries.
  // ---------------------------------------------------------------------
  class CsvStreamParser {
    constructor(onRow) {
      this.onRow = onRow;        // return false to stop parsing
      this.row = [];
      this.field = '';
      this.inQuotes = false;
      this.quotePending = false; // saw '"' at chunk end while in quotes
      this.fieldStarted = false; // any char (or quote) seen in this field
      this.skipLF = false;       // previous chunk ended with '\r'
      this.stopped = false;
    }

    push(chunk) {
      if (this.stopped || chunk.length === 0) return;
      let i = 0;
      const len = chunk.length;

      if (this.skipLF) {
        this.skipLF = false;
        if (chunk.charCodeAt(0) === 10) i = 1;
      }
      if (this.quotePending) {
        this.quotePending = false;
        if (chunk.charCodeAt(i) === 34) { this.field += '"'; i++; }
        else this.inQuotes = false;
      }

      while (i < len) {
        if (this.inQuotes) {
          const q = chunk.indexOf('"', i);
          if (q === -1) { this.field += chunk.slice(i); return; }
          this.field += chunk.slice(i, q);
          i = q + 1;
          if (i >= len) { this.quotePending = true; return; }
          if (chunk.charCodeAt(i) === 34) { this.field += '"'; i++; }
          else this.inQuotes = false;
          continue;
        }

        // Unquoted region: scan until a delimiter, line break or quote.
        let start = i;
        while (i < len) {
          const c = chunk.charCodeAt(i);
          if (c === 44 || c === 10 || c === 13 || c === 34) break;
          i++;
        }
        if (i > start) { this.field += chunk.slice(start, i); this.fieldStarted = true; }
        if (i >= len) return;

        const c = chunk.charCodeAt(i);
        i++;
        if (c === 34) {
          if (!this.fieldStarted) { this.inQuotes = true; this.fieldStarted = true; }
          else this.field += '"'; // stray quote inside an unquoted field: keep it
        } else if (c === 44) {
          this.endField();
        } else { // \n or \r
          this.endField();
          if (!this.endRow()) return;
          if (c === 13) {
            if (i < len) { if (chunk.charCodeAt(i) === 10) i++; }
            else this.skipLF = true;
          }
        }
      }
    }

    end() {
      if (this.stopped) return;
      if (this.quotePending) { this.quotePending = false; this.inQuotes = false; }
      if (this.fieldStarted || this.row.length > 0) {
        this.endField();
        this.endRow();
      }
    }

    endField() {
      this.row.push(this.field);
      this.field = '';
      this.fieldStarted = false;
    }

    endRow() {
      const row = this.row;
      this.row = [];
      if (row.length === 1 && row[0] === '') return true; // blank line
      if (this.onRow(row) === false) { this.stopped = true; return false; }
      return true;
    }
  }

  // ---------------------------------------------------------------------
  // 64-bit hashing + open-addressing hash set on typed arrays. Holding
  // millions of dedupe keys as JS strings would exhaust memory; this costs
  // ~16 bytes per entry with a ~1-in-10^12 collision chance at 10M rows.
  // ---------------------------------------------------------------------
  function hash64(str) {
    let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
    for (let i = 0; i < str.length; i++) {
      const ch = str.charCodeAt(i);
      h1 = Math.imul(h1 ^ ch, 2654435761);
      h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
    h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
    h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return [h1 >>> 0, h2 >>> 0];
  }

  class HashSet64 {
    constructor(initialCapacity = 1 << 16) {
      this.cap = initialCapacity;
      this.mask = this.cap - 1;
      this.table = new Uint32Array(this.cap * 2);
      this.size = 0;
    }

    // Returns true if the key was newly added, false if already present.
    add(a, b) {
      if (a === 0 && b === 0) b = 1; // (0,0) marks an empty slot
      if ((this.size + 1) * 2 > this.cap) this.grow();
      return this.insert(this.table, this.mask, a, b);
    }

    insert(table, mask, a, b) {
      let slot = (a ^ Math.imul(b, 0x9e3779b1)) & mask;
      for (;;) {
        const p = slot * 2;
        const ta = table[p], tb = table[p + 1];
        if (ta === 0 && tb === 0) {
          table[p] = a; table[p + 1] = b;
          if (table === this.table) this.size++;
          return true;
        }
        if (ta === a && tb === b) return false;
        slot = (slot + 1) & mask;
      }
    }

    grow() {
      const old = this.table;
      this.cap *= 2;
      this.mask = this.cap - 1;
      const next = new Uint32Array(this.cap * 2);
      for (let p = 0; p < old.length; p += 2) {
        if (old[p] !== 0 || old[p + 1] !== 0) this.insert(next, this.mask, old[p], old[p + 1]);
      }
      this.table = next;
    }
  }

  // ---------------------------------------------------------------------
  // Column helpers
  // ---------------------------------------------------------------------
  const KEY_ALIASES = {
    plugin: ['plugin id', 'plugin', 'pluginid', 'plugin_id'],
    host: ['host', 'ip address', 'ip', 'asset ip', 'ipv4', 'hostname', 'dns name', 'netbios name'],
    protocol: ['protocol'],
    port: ['port'],
    cve: ['cve'],
    risk: ['risk', 'severity', 'risk factor'],
  };
  const INFO_LEVELS = new Set(['none', 'info', 'informational']);

  function normalizeHeader(h) {
    return h.replace(/^﻿/, '').trim();
  }

  function findColumn(headers, aliases) {
    const lower = headers.map(h => h.toLowerCase());
    for (const alias of aliases) {
      const idx = lower.indexOf(alias);
      if (idx !== -1) return idx;
    }
    return -1;
  }

  // Exclusion rules: { column, op, values: string[] }. Returns matchers
  // whose test(cell) is true when the row should be dropped.
  function compileRules(rules) {
    return (rules || []).map((rule, i) => {
      const values = rule.values.map(v => v.trim()).filter(Boolean);
      let test;
      if (rule.op === 'in' || rule.op === 'notin') {
        const set = new Set();
        const ranges = [];
        for (const v of values) {
          const m = /^(\d+)\s*-\s*(\d+)$/.exec(v);
          if (m) ranges.push([Math.min(+m[1], +m[2]), Math.max(+m[1], +m[2])]);
          else set.add(v.toLowerCase());
        }
        const isIn = cell => {
          const c = cell.trim().toLowerCase();
          if (set.has(c)) return true;
          if (ranges.length && /^\d+$/.test(c)) {
            const n = +c;
            for (const [a, b] of ranges) if (n >= a && n <= b) return true;
          }
          return false;
        };
        test = rule.op === 'in' ? isIn : cell => !isIn(cell);
      } else if (rule.op === 'contains') {
        const needles = values.map(v => v.toLowerCase());
        test = cell => {
          const c = cell.toLowerCase();
          for (const n of needles) if (c.indexOf(n) !== -1) return true;
          return false;
        };
      } else if (rule.op === 'regex') {
        const res = values.map(v => new RegExp(v, 'i'));
        test = cell => {
          for (const re of res) if (re.test(cell)) return true;
          return false;
        };
      } else {
        throw new Error('Unknown rule operator: ' + rule.op);
      }
      return { index: i, key: rule.column.trim().toLowerCase(), test };
    });
  }

  function csvEscape(v) {
    return '"' + (v.indexOf('"') === -1 ? v : v.replace(/"/g, '""')) + '"';
  }

  // ---------------------------------------------------------------------
  // Reading
  // ---------------------------------------------------------------------
  async function readHeader(file) {
    let headers = null;
    const parser = new CsvStreamParser(row => { headers = row; return false; });
    const decoder = new TextDecoder('utf-8');
    let offset = 0;
    while (!headers && offset < file.size) {
      const end = Math.min(file.size, offset + 256 * 1024);
      const buf = await file.slice(offset, end).arrayBuffer();
      offset = end;
      parser.push(decoder.decode(buf, { stream: offset < file.size }));
    }
    if (!headers) parser.end();
    if (!headers) throw new Error('File is empty or has no header row');
    return headers.map(normalizeHeader);
  }

  function describeFile(headers) {
    const has = key => findColumn(headers, KEY_ALIASES[key]) !== -1;
    const recognized = has('plugin') && has('host');
    return { recognized, hasRisk: has('risk') };
  }

  // Streams a File through the parser. afterChunk(bytes) is awaited after
  // every read so the caller can flush output and apply backpressure.
  async function streamFile(file, parser, afterChunk, isCancelled) {
    const decoder = new TextDecoder('utf-8');
    for (let offset = 0; offset < file.size; offset += READ_CHUNK) {
      if (isCancelled()) return;
      const buf = await file.slice(offset, offset + READ_CHUNK).arrayBuffer();
      parser.push(decoder.decode(buf, { stream: true }));
      await afterChunk(buf.byteLength);
      if (parser.stopped) return;
    }
    parser.push(decoder.decode());
    parser.end();
  }

  // ---------------------------------------------------------------------
  // Writing — straight to disk via the File System Access API when the
  // page handed us a file handle, otherwise into a disk-backable Blob.
  // ---------------------------------------------------------------------
  class OutputSink {
    constructor(writable) {
      this.writable = writable;
      this.buf = [];
      this.bufLen = 0;
      this.blobParts = [];
      this.pending = [];
      this.pendingLen = 0;
    }

    // Synchronous append; caller awaits maybeFlush() between chunks.
    append(str) {
      this.buf.push(str);
      this.bufLen += str.length;
    }

    get needsFlush() { return this.bufLen >= FLUSH_CHARS; }

    async flush() {
      if (this.bufLen === 0) return;
      const text = this.buf.join('');
      this.buf = [];
      this.bufLen = 0;
      if (this.writable) {
        await this.writable.write(text);
      } else {
        this.pending.push(text);
        this.pendingLen += text.length;
        if (this.pendingLen >= BLOB_PART_CHARS) this.foldPending();
      }
    }

    foldPending() {
      if (this.pending.length === 0) return;
      this.blobParts.push(new Blob(this.pending, { type: 'text/csv' }));
      this.pending = [];
      this.pendingLen = 0;
    }

    async close() {
      await this.flush();
      if (this.writable) { await this.writable.close(); return null; }
      this.foldPending();
      return new Blob(this.blobParts, { type: 'text/csv;charset=utf-8' });
    }

    async abort() {
      this.buf = []; this.pending = []; this.blobParts = [];
      if (this.writable) { try { await this.writable.abort(); } catch (_) { /* already closed */ } }
    }
  }

  // ---------------------------------------------------------------------
  // Merge
  // ---------------------------------------------------------------------
  let cancelled = false;

  async function merge(msg) {
    cancelled = false;
    const { files, columns, options, outputHandle } = msg;
    const isCancelled = () => cancelled;
    const outCols = columns.slice();
    const sourceIdx = options.addSource ? outCols.length : -1;
    if (options.addSource) outCols.push('Source File');

    // Some browsers can't open a writable from a worker; fall back to a Blob
    // and let the page write it to the chosen file instead.
    let writable = null;
    if (outputHandle && typeof outputHandle.createWritable === 'function') {
      try { writable = await outputHandle.createWritable(); } catch (_) { writable = null; }
    }
    const sink = new OutputSink(writable);

    const totalBytes = files.reduce((s, f) => s + f.size, 0);
    let bytesDone = 0;
    let lastProgress = 0;
    const seen = options.dedupe === 'none' ? null : new HashSet64();
    const hosts = new Set();
    const severity = Object.create(null);
    const totals = { rowsIn: 0, rowsOut: 0, duplicates: 0, filtered: 0, excluded: 0, malformed: 0 };
    const rules = compileRules(options.rules);
    const ruleHits = rules.map(() => 0);
    const perFile = [];

    const outColIndex = new Map(outCols.map((c, i) => [c.toLowerCase(), i]));

    try {
      if (options.bom) sink.append('﻿');
      sink.append(outCols.map(csvEscape).join(',') + '\n');

      for (let fi = 0; fi < files.length; fi++) {
        if (cancelled) break;
        const file = files[fi];
        const stats = { rowsIn: 0, rowsOut: 0, duplicates: 0, filtered: 0, excluded: 0, malformed: 0, error: null };
        let map = null;        // file column index -> output column index (or -1)
        let fileCols = 0;
        // Key columns come from the file itself so dedupe/filter still work
        // when the user has deselected those columns from the output.
        let fKey = null;
        let fRules = null;     // rules whose column exists in this file
        const blank = new Array(outCols.length);

        const parser = new CsvStreamParser(row => {
          if (map === null) {
            const headers = row.map(normalizeHeader);
            fileCols = headers.length;
            map = headers.map(h => {
              const idx = outColIndex.get(h.toLowerCase());
              return idx === undefined || idx === sourceIdx ? -1 : idx;
            });
            fKey = {};
            for (const k of Object.keys(KEY_ALIASES)) fKey[k] = findColumn(headers, KEY_ALIASES[k]);
            const lower = headers.map(h => h.toLowerCase());
            fRules = rules
              .map(r => ({ ...r, col: lower.indexOf(r.key) }))
              .filter(r => r.col !== -1);
            return;
          }

          stats.rowsIn++;
          if (row.length !== fileCols) stats.malformed++;

          if (options.excludeInfo && fKey.risk !== -1) {
            const sev = (row[fKey.risk] || '').trim().toLowerCase();
            if (INFO_LEVELS.has(sev)) { stats.filtered++; return; }
          }

          for (let r = 0; r < fRules.length; r++) {
            const rule = fRules[r];
            if (rule.test(row[rule.col] || '')) {
              stats.excluded++;
              ruleHits[rule.index]++;
              return;
            }
          }

          const out = blank.slice();
          for (let i = 0; i < row.length && i < map.length; i++) {
            const o = map[i];
            if (o !== -1) out[o] = row[i];
          }

          if (seen) {
            let key;
            if (options.dedupe === 'key' && fKey.plugin !== -1 && fKey.host !== -1) {
              const g = k => (fKey[k] === -1 ? '' : (row[fKey[k]] || '').trim().toLowerCase());
              key = g('plugin') + '\x1f' + g('host') + '\x1f' + g('protocol') + '\x1f' + g('port') + '\x1f' + g('cve');
            } else {
              // Exact duplicate: compare the whole source row.
              key = row.join('\x1f');
            }
            const [a, b] = hash64(key);
            if (!seen.add(a, b)) { stats.duplicates++; return; }
          }

          if (sourceIdx !== -1) out[sourceIdx] = file.name;

          let line = '';
          for (let i = 0; i < out.length; i++) {
            if (i) line += ',';
            const v = out[i];
            line += v === undefined ? '""' : csvEscape(v);
          }
          sink.append(line + '\n');
          stats.rowsOut++;

          if (fKey.host !== -1) {
            const h = row[fKey.host];
            if (h) hosts.add(h.trim());
          }
          if (fKey.risk !== -1) {
            const s = (row[fKey.risk] || '').trim() || 'Unspecified';
            severity[s] = (severity[s] || 0) + 1;
          }
        });

        try {
          await streamFile(file, parser, async n => {
            bytesDone += n;
            if (sink.needsFlush) await sink.flush();
            const now = Date.now();
            if (now - lastProgress > PROGRESS_INTERVAL_MS) {
              lastProgress = now;
              self.postMessage({
                type: 'progress', fileIndex: fi, bytesDone, totalBytes,
                rowsOut: totals.rowsOut + stats.rowsOut,
              });
            }
          }, isCancelled);
        } catch (err) {
          stats.error = String(err && err.message || err);
        }

        await sink.flush();
        for (const k of ['rowsIn', 'rowsOut', 'duplicates', 'filtered', 'excluded', 'malformed']) totals[k] += stats[k];
        perFile.push(stats);
        self.postMessage({ type: 'fileDone', fileIndex: fi, stats });
      }

      if (cancelled) {
        await sink.abort();
        self.postMessage({ type: 'cancelled' });
        return;
      }

      const blob = await sink.close();
      self.postMessage({
        type: 'done',
        blob,
        stats: {
          ...totals,
          columns: outCols.length,
          uniqueHosts: hosts.size,
          severity,
          perFile,
          ruleHits,
          bytesIn: totalBytes,
          bytesOut: blob ? blob.size : null,
        },
      });
    } catch (err) {
      await sink.abort();
      throw err;
    }
  }

  // ---------------------------------------------------------------------
  // Message handling
  // ---------------------------------------------------------------------
  self.onmessage = async e => {
    const msg = e.data;
    try {
      if (msg.type === 'scan') {
        for (const { id, file } of msg.files) {
          try {
            const headers = await readHeader(file);
            self.postMessage({ type: 'scanResult', id, headers, ...describeFile(headers) });
          } catch (err) {
            self.postMessage({ type: 'scanResult', id, error: String(err && err.message || err) });
          }
        }
      } else if (msg.type === 'merge') {
        await merge(msg);
      } else if (msg.type === 'cancel') {
        cancelled = true;
      }
    } catch (err) {
      self.postMessage({ type: 'error', message: String(err && err.message || err) });
    }
  };

  // Exposed for the Node test harness; harmless in the browser.
  self.__mergeInternals = { CsvStreamParser, HashSet64, hash64, readHeader, compileRules };
}
