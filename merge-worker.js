/*
 * Merge engine. Everything lives inside mergeWorkerMain so app.js can
 * serialise it into a Blob-URL worker — that keeps the app working when
 * index.html is opened straight from disk (file://), where
 * `new Worker('merge-worker.js')` would be blocked.
 */
function mergeWorkerMain() {
  'use strict';

  const READ_CHUNK = 4 * 1024 * 1024;        // bytes per file read
  const PROBE_CHUNK = 256 * 1024;            // bytes per read when sniffing headers
  const FLUSH_SIZE = 4 * 1024 * 1024;        // chars/bytes buffered before a write
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
  // Sources. A source is a plain File (.csv / .nessus) or one entry inside
  // a .zip: { file, entry?, kind: 'csv' | 'nessus', name }.
  // ---------------------------------------------------------------------
  function kindOf(name) {
    const m = /\.([a-z0-9]+)$/i.exec(name);
    const ext = m ? m[1].toLowerCase() : '';
    return ext === 'csv' || ext === 'nessus' || ext === 'zip' ? ext : null;
  }

  async function readView(file, start, end) {
    return new DataView(await file.slice(start, end).arrayBuffer());
  }

  // Lists a ZIP's files from its central directory (Zip64 aware). Nothing
  // is decompressed here.
  async function listZip(file) {
    const tailLen = Math.min(file.size, 65557);
    const tail = await readView(file, file.size - tailLen, file.size);
    let eocd = -1;
    for (let i = tail.byteLength - 22; i >= 0; i--) {
      if (tail.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
    }
    if (eocd === -1) throw new Error('Not a valid ZIP archive');
    let count = tail.getUint16(eocd + 10, true);
    let cdSize = tail.getUint32(eocd + 12, true);
    let cdOffset = tail.getUint32(eocd + 16, true);
    if (count === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
      const loc = eocd - 20; // Zip64 end-of-central-directory locator
      if (loc < 0 || tail.getUint32(loc, true) !== 0x07064b50) throw new Error('Unsupported ZIP64 archive');
      const e64Offset = Number(tail.getBigUint64(loc + 8, true));
      const e64 = await readView(file, e64Offset, e64Offset + 56);
      if (e64.getUint32(0, true) !== 0x06064b50) throw new Error('Corrupt ZIP64 archive');
      count = Number(e64.getBigUint64(32, true));
      cdSize = Number(e64.getBigUint64(40, true));
      cdOffset = Number(e64.getBigUint64(48, true));
    }

    const cd = await readView(file, cdOffset, cdOffset + cdSize);
    const bytes = new Uint8Array(cd.buffer, cd.byteOffset, cd.byteLength);
    const decoder = new TextDecoder('utf-8');
    const entries = [];
    let p = 0;
    for (let n = 0; n < count && p + 46 <= cd.byteLength; n++) {
      if (cd.getUint32(p, true) !== 0x02014b50) throw new Error('Corrupt ZIP central directory');
      const flags = cd.getUint16(p + 8, true);
      const method = cd.getUint16(p + 10, true);
      let compSize = cd.getUint32(p + 20, true);
      let size = cd.getUint32(p + 24, true);
      const nameLen = cd.getUint16(p + 28, true);
      const extraLen = cd.getUint16(p + 30, true);
      const commentLen = cd.getUint16(p + 32, true);
      let localOffset = cd.getUint32(p + 42, true);
      const name = decoder.decode(bytes.subarray(p + 46, p + 46 + nameLen));
      // Zip64 extra field holds the real values of fields saturated at 0xffffffff.
      let q = p + 46 + nameLen;
      const extraEnd = q + extraLen;
      while (q + 4 <= extraEnd) {
        const id = cd.getUint16(q, true);
        const len = cd.getUint16(q + 2, true);
        if (id === 0x0001) {
          let r = q + 4;
          if (size === 0xffffffff) { size = Number(cd.getBigUint64(r, true)); r += 8; }
          if (compSize === 0xffffffff) { compSize = Number(cd.getBigUint64(r, true)); r += 8; }
          if (localOffset === 0xffffffff) { localOffset = Number(cd.getBigUint64(r, true)); }
        }
        q += 4 + len;
      }
      p = extraEnd + commentLen;
      if (!name.endsWith('/')) entries.push({ name, flags, method, compSize, size, localOffset });
    }
    return entries;
  }

  const sourceBytes = src => (src.entry ? src.entry.compSize : src.file.size);

  // Yields { text, bytes } — decoded text plus how many bytes of the input
  // file were consumed, for progress. Breaking out of the loop early stops
  // reading (and decompressing) immediately.
  async function* textChunks(src, chunkSize = READ_CHUNK) {
    const decoder = new TextDecoder('utf-8');
    const { file, entry } = src;
    let blob = file;
    if (entry) {
      if (entry.flags & 1) throw new Error('Encrypted ZIP entries are not supported');
      const lh = await readView(file, entry.localOffset, entry.localOffset + 30);
      if (lh.getUint32(0, true) !== 0x04034b50) throw new Error('Corrupt ZIP entry');
      const start = entry.localOffset + 30 + lh.getUint16(26, true) + lh.getUint16(28, true);
      blob = file.slice(start, start + entry.compSize);
      if (entry.method !== 0 && entry.method !== 8) {
        throw new Error(`Unsupported ZIP compression method (${entry.method})`);
      }
    }

    if (!entry || entry.method === 0) {
      for (let offset = 0; offset < blob.size; offset += chunkSize) {
        const buf = await blob.slice(offset, offset + chunkSize).arrayBuffer();
        yield { text: decoder.decode(buf, { stream: true }), bytes: buf.byteLength };
      }
    } else {
      if (typeof DecompressionStream !== 'function') {
        throw new Error('This browser cannot unzip files. Use a current Chrome, Edge, Firefox or Safari.');
      }
      let consumed = 0;
      let reported = 0;
      const counted = blob.stream().pipeThrough(new TransformStream({
        transform(chunk, ctl) { consumed += chunk.byteLength; ctl.enqueue(chunk); },
      }));
      const reader = counted.pipeThrough(new DecompressionStream('deflate-raw')).getReader();
      try {
        let pending = '';
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          pending += decoder.decode(value, { stream: true });
          // Batch the small decompressed chunks to keep per-chunk overhead low.
          if (pending.length >= chunkSize) {
            const text = pending;
            pending = '';
            const bytes = consumed - reported;
            reported = consumed;
            yield { text, bytes };
          }
        }
        yield { text: pending, bytes: blob.size - reported };
      } finally {
        reader.cancel().catch(() => {});
      }
    }
    const rest = decoder.decode();
    if (rest) yield { text: rest, bytes: 0 };
  }

  // ---------------------------------------------------------------------
  // .nessus (NessusClientData_v2) streaming reader. Buffers one ReportHost
  // at a time and turns each ReportItem into rows shaped like Tenable's CSV
  // export — one row per CVE — so they merge cleanly with CSV reports.
  // ---------------------------------------------------------------------
  const NESSUS_COLUMNS = [
    'Plugin ID', 'CVE', 'CVSS v2.0 Base Score', 'Risk', 'Host', 'Protocol', 'Port', 'Name',
    'Synopsis', 'Description', 'Solution', 'See Also', 'Plugin Output',
    'CVSS v3.0 Base Score', 'CVSS v4.0 Base Score', 'VPR Score', 'EPSS Score', 'STIG Severity',
    'BID', 'XREF', 'MSKB', 'Plugin Publication Date', 'Plugin Modification Date', 'Patch Publication Date',
    'Exploit Available', 'Metasploit', 'Core Impact', 'CANVAS', 'Plugin Family', 'Service',
    'IP Address', 'FQDN', 'NetBIOS Name', 'OS', 'MAC Address', 'Scan Name', 'Scan Start', 'Scan End',
  ];
  const SEVERITY_NAMES = ['None', 'Low', 'Medium', 'High', 'Critical'];
  const XML_ENTITIES = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };

  function decodeEntities(s) {
    if (s.indexOf('&') === -1) return s;
    return s.replace(/&(#[xX][0-9a-fA-F]+|#[0-9]+|[a-zA-Z]+);/g, (m, e) => {
      if (e[0] === '#') {
        const cp = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
        try { return String.fromCodePoint(cp); } catch (_) { return m; }
      }
      return XML_ENTITIES[e] !== undefined ? XML_ENTITIES[e] : m;
    });
  }

  // Element text: entities decoded, CDATA sections taken verbatim.
  function xmlText(s) {
    if (s.indexOf('<![CDATA[') === -1) return decodeEntities(s);
    let out = '';
    let i = 0;
    while (i < s.length) {
      const c = s.indexOf('<![CDATA[', i);
      if (c === -1) { out += decodeEntities(s.slice(i)); break; }
      out += decodeEntities(s.slice(i, c));
      const e = s.indexOf(']]>', c + 9);
      if (e === -1) { out += s.slice(c + 9); break; }
      out += s.slice(c + 9, e);
      i = e + 3;
    }
    return out;
  }

  function parseAttrs(s) {
    const attrs = {};
    const re = /([\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
    let m;
    while ((m = re.exec(s))) attrs[m[1]] = decodeEntities(m[2] !== undefined ? m[2] : m[3]);
    return attrs;
  }

  // Index of the '>' closing a start tag, skipping quoted attribute values.
  function tagEnd(s, i) {
    let quote = 0;
    for (; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (quote) { if (c === quote) quote = 0; }
      else if (c === 34 || c === 39) quote = c;
      else if (c === 62) return i;
    }
    return -1;
  }

  const CHILD_RE = /<([A-Za-z_][\w.:-]*)\b[^>]*?(?:\/>|>([\s\S]*?)<\/\1\s*>)/g;
  const HOST_TAG_RE = /<tag\s+name\s*=\s*"([^"]*)"\s*>([\s\S]*?)<\/tag\s*>/g;
  const REPORT_RE = /<Report\s[^>]*?name\s*=\s*"([^"]*)"/g;

  class NessusStreamParser {
    constructor(onRow) {
      this.onRow = onRow;   // return false to stop
      this.buf = '';
      this.closeFrom = 0;   // where to resume searching for </ReportHost>
      this.report = '';
      this.stopped = false;
    }

    push(text) {
      if (this.stopped) return;
      this.buf += text;
      for (;;) {
        const start = this.hostStart();
        if (start === -1) {
          this.noteReport(this.buf);
          // Keep a tail in case a tag is split across chunks.
          this.buf = this.buf.slice(-1024);
          this.closeFrom = 0;
          return;
        }
        if (start > 0) {
          this.noteReport(this.buf.slice(0, start));
          this.buf = this.buf.slice(start);
          this.closeFrom = 0;
        }
        const end = this.buf.indexOf('</ReportHost>', this.closeFrom);
        if (end === -1) {
          this.closeFrom = Math.max(0, this.buf.length - 13);
          return;
        }
        const block = this.buf.slice(0, end);
        this.buf = this.buf.slice(end + 13);
        this.closeFrom = 0;
        this.host(block);
        if (this.stopped) return;
      }
    }

    end() {
      if (!this.stopped && this.hostStart() !== -1) {
        throw new Error('File ended in the middle of a host (truncated download?)');
      }
    }

    hostStart() {
      let i = 0;
      for (;;) {
        i = this.buf.indexOf('<ReportHost', i);
        if (i === -1) return -1;
        const c = this.buf.charCodeAt(i + 11);
        if (c === 32 || c === 62 || c === 9 || c === 10 || c === 13) return i;
        if (Number.isNaN(c)) return i; // tag name may continue in the next chunk
        i += 11;
      }
    }

    noteReport(s) {
      REPORT_RE.lastIndex = 0;
      let m;
      while ((m = REPORT_RE.exec(s))) this.report = decodeEntities(m[1]);
    }

    host(block) {
      const openEnd = tagEnd(block, 0);
      if (openEnd === -1) return;
      const name = parseAttrs(block.slice(11, openEnd)).name || '';
      const props = Object.create(null);
      let i = openEnd + 1;
      const hp = block.indexOf('<HostProperties', i);
      if (hp !== -1) {
        const hpEnd = block.indexOf('</HostProperties>', hp);
        const section = block.slice(hp, hpEnd === -1 ? block.length : hpEnd);
        HOST_TAG_RE.lastIndex = 0;
        let m;
        while ((m = HOST_TAG_RE.exec(section))) props[decodeEntities(m[1])] = xmlText(m[2]);
        if (hpEnd !== -1) i = hpEnd;
      }
      const host = {
        name, report: this.report,
        ip: props['host-ip'] || '', fqdn: props['host-fqdn'] || '', netbios: props['netbios-name'] || '',
        os: props['operating-system'] || '', mac: props['mac-address'] || '',
        start: props.HOST_START || '', end: props.HOST_END || '',
      };

      for (;;) {
        const idx = block.indexOf('<ReportItem', i);
        if (idx === -1) return;
        const te = tagEnd(block, idx);
        if (te === -1) return;
        const attrs = parseAttrs(block.slice(idx + 11, te));
        let body = '';
        if (block.charCodeAt(te - 1) === 47) { // self-closing <ReportItem ... />
          i = te + 1;
        } else {
          const close = block.indexOf('</ReportItem>', te);
          body = block.slice(te + 1, close === -1 ? block.length : close);
          i = close === -1 ? block.length : close + 13;
        }
        if (this.item(host, attrs, body) === false) { this.stopped = true; return; }
      }
    }

    item(host, a, body) {
      const f = Object.create(null);
      CHILD_RE.lastIndex = 0;
      let m;
      while ((m = CHILD_RE.exec(body))) {
        (f[m[1]] || (f[m[1]] = [])).push(m[2] === undefined ? '' : xmlText(m[2]).trim());
      }
      const one = k => (f[k] ? f[k][0] : '');
      const many = k => (f[k] ? f[k].join(', ') : '');
      const row = [
        a.pluginID || '', '', one('cvss_base_score'),
        one('risk_factor') || SEVERITY_NAMES[+a.severity] || '',
        host.name, a.protocol || '', a.port || '', a.pluginName || '',
        one('synopsis'), one('description'), one('solution'), one('see_also'), one('plugin_output'),
        one('cvss3_base_score'), one('cvss4_base_score'), one('vpr_score'), one('epss_score'), one('stig_severity'),
        many('bid'), many('xref'), many('mskb'),
        one('plugin_publication_date'), one('plugin_modification_date'), one('patch_publication_date'),
        one('exploit_available'), one('exploit_framework_metasploit'), one('exploit_framework_core'),
        one('exploit_framework_canvas'), a.pluginFamily || '', a.svc_name || '',
        host.ip, host.fqdn, host.netbios, host.os, host.mac, host.report, host.start, host.end,
      ];
      const cves = f.cve;
      if (!cves || cves.length === 0) return this.onRow(row);
      for (const cve of cves) {
        const r = row.slice();
        r[1] = cve;
        if (this.onRow(r) === false) return false;
      }
      return true;
    }
  }

  // Reads just enough of a source to learn its columns.
  async function probe(src) {
    if (src.kind === 'csv') {
      let headers = null;
      const parser = new CsvStreamParser(row => { headers = row; return false; });
      for await (const { text } of textChunks(src, PROBE_CHUNK)) {
        parser.push(text);
        if (headers) break;
      }
      if (!headers) parser.end();
      if (!headers) throw new Error('File is empty or has no header row');
      headers = headers.map(normalizeHeader);
      return { headers, ...describeFile(headers) };
    }
    let head = '';
    for await (const { text } of textChunks(src, PROBE_CHUNK)) {
      head += text;
      if (head.length >= 64 * 1024) break;
    }
    if (!/<NessusClientData_v2[\s>]/.test(head)) throw new Error('Not a .nessus (NessusClientData_v2) file');
    return { headers: NESSUS_COLUMNS.slice(), recognized: true };
  }

  async function scanFile(file) {
    const kind = kindOf(file.name);
    if (kind !== 'zip') return probe({ file, kind });

    const children = [];
    let nested = 0;
    for (const entry of await listZip(file)) {
      const base = entry.name.split('/').pop();
      if (entry.name.startsWith('__MACOSX/') || base.startsWith('._')) continue;
      const k = kindOf(entry.name);
      if (k === 'zip') { nested++; continue; }
      if (!k) continue;
      try {
        children.push({ name: entry.name, kind: k, size: entry.size, entry, ...(await probe({ file, entry, kind: k })) });
      } catch (err) {
        children.push({ name: entry.name, kind: k, size: entry.size, entry, error: String(err && err.message || err) });
      }
    }
    return { children, nested };
  }

  function describeFile(headers) {
    const has = key => findColumn(headers, KEY_ALIASES[key]) !== -1;
    return { recognized: has('plugin') && has('host') };
  }

  // ---------------------------------------------------------------------
  // Writing — straight to disk via the File System Access API when the
  // page handed us a file handle, otherwise into a Blob (which browsers can
  // page out to disk).
  // ---------------------------------------------------------------------
  class OutputSink {
    constructor(writable) {
      this.writable = writable;
      this.buf = [];
      this.bufLen = 0;
      this.onlyStrings = true;
      this.parts = [];
    }

    // Accepts strings (CSV) or Uint8Arrays (XLSX). Synchronous; the merge
    // loop awaits flush() between input chunks.
    append(chunk) {
      this.buf.push(chunk);
      this.bufLen += chunk.length;
      if (typeof chunk !== 'string') this.onlyStrings = false;
    }

    get needsFlush() { return this.bufLen >= FLUSH_SIZE; }

    async flush() {
      if (this.bufLen === 0) return;
      const blob = new Blob(this.onlyStrings ? [this.buf.join('')] : this.buf);
      this.buf = [];
      this.bufLen = 0;
      this.onlyStrings = true;
      if (this.writable) await this.writable.write(blob);
      else this.parts.push(blob);
    }

    async close(type) {
      await this.flush();
      if (this.writable) { await this.writable.close(); return null; }
      return new Blob(this.parts, { type });
    }

    async abort() {
      this.buf = [];
      this.parts = [];
      if (this.writable) { try { await this.writable.abort(); } catch (_) { /* already closed */ } }
    }
  }

  class CsvOutput {
    constructor(sink, cols, bom) {
      this.sink = sink;
      this.mime = 'text/csv;charset=utf-8';
      if (bom) sink.append('﻿');
      sink.append(cols.map(csvEscape).join(',') + '\n');
    }

    row(values) {
      let line = '';
      for (let i = 0; i < values.length; i++) {
        if (i) line += ',';
        const v = values[i];
        line += v === undefined ? '""' : csvEscape(v);
      }
      this.sink.append(line + '\n');
    }

    get needsFlush() { return this.sink.needsFlush; }
    flush() { return this.sink.flush(); }
    async finish() { return {}; }
  }

  // ---------------------------------------------------------------------
  // Minimal streaming ZIP writer (for .xlsx). Big entries are deflated via
  // CompressionStream with sizes in a trailing data descriptor, so nothing
  // has to be held in memory.
  // ---------------------------------------------------------------------
  const CRC_TABLE = (() => {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      t[n] = c >>> 0;
    }
    return t;
  })();

  function crc32(crc, bytes) {
    crc = ~crc;
    for (let i = 0; i < bytes.length; i++) crc = CRC_TABLE[(crc ^ bytes[i]) & 255] ^ (crc >>> 8);
    return ~crc >>> 0;
  }

  const ZIP_LIMIT = 0xffffffff;
  const ZIP_TOO_BIG = 'The workbook would exceed 4 GB, which Excel cannot open. Use CSV output, or exclude columns or findings to shrink it.';

  class ZipWriter {
    constructor(sink) {
      this.sink = sink;
      this.offset = 0;
      this.entries = [];
      this.enc = new TextEncoder();
      const d = new Date();
      this.time = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1);
      this.date = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
    }

    put(bytes) {
      this.sink.append(bytes);
      this.offset += bytes.length;
      if (this.offset > ZIP_LIMIT) throw new Error(ZIP_TOO_BIG);
    }

    localHeader(nameBytes, flags, method, crc, csize, size) {
      const h = new DataView(new ArrayBuffer(30));
      h.setUint32(0, 0x04034b50, true);
      h.setUint16(4, 20, true);
      h.setUint16(6, flags, true);
      h.setUint16(8, method, true);
      h.setUint16(10, this.time, true);
      h.setUint16(12, this.date, true);
      h.setUint32(14, crc, true);
      h.setUint32(18, csize, true);
      h.setUint32(22, size, true);
      h.setUint16(26, nameBytes.length, true);
      return new Uint8Array(h.buffer);
    }

    // Small entry, stored uncompressed.
    addFile(name, text) {
      const nameBytes = this.enc.encode(name);
      const data = this.enc.encode(text);
      const crc = crc32(0, data);
      const offset = this.offset;
      this.put(this.localHeader(nameBytes, 0x0800, 0, crc, data.length, data.length));
      this.put(nameBytes);
      this.put(data);
      this.entries.push({ nameBytes, flags: 0x0800, method: 0, crc, csize: data.length, size: data.length, offset });
    }

    // Large entry, deflated as it is written.
    openStream(name) {
      const nameBytes = this.enc.encode(name);
      const offset = this.offset;
      const flags = 0x0808; // UTF-8 name + data descriptor
      this.put(this.localHeader(nameBytes, flags, 8, 0, 0, 0));
      this.put(nameBytes);

      const cs = new CompressionStream('deflate-raw');
      const writer = cs.writable.getWriter();
      const reader = cs.readable.getReader();
      const st = { crc: 0, size: 0, csize: 0 };
      const pump = (async () => {
        try {
          for (;;) {
            const { done, value } = await reader.read();
            if (done) return;
            st.csize += value.length;
            this.put(value);
          }
        } catch (err) {
          writer.abort(err).catch(() => {});
          throw err;
        }
      })();
      pump.catch(() => {}); // surfaced through write()/close()

      return {
        write: async text => {
          const bytes = this.enc.encode(text);
          st.crc = crc32(st.crc, bytes);
          st.size += bytes.length;
          if (st.size > ZIP_LIMIT) throw new Error(ZIP_TOO_BIG);
          await writer.write(bytes);
        },
        close: async () => {
          await writer.close();
          await pump;
          const d = new DataView(new ArrayBuffer(16));
          d.setUint32(0, 0x08074b50, true);
          d.setUint32(4, st.crc, true);
          d.setUint32(8, st.csize, true);
          d.setUint32(12, st.size, true);
          this.put(new Uint8Array(d.buffer));
          this.entries.push({ nameBytes, flags, method: 8, crc: st.crc, csize: st.csize, size: st.size, offset });
        },
      };
    }

    finish() {
      const cdStart = this.offset;
      for (const e of this.entries) {
        const h = new DataView(new ArrayBuffer(46));
        h.setUint32(0, 0x02014b50, true);
        h.setUint16(4, 20, true);
        h.setUint16(6, 20, true);
        h.setUint16(8, e.flags, true);
        h.setUint16(10, e.method, true);
        h.setUint16(12, this.time, true);
        h.setUint16(14, this.date, true);
        h.setUint32(16, e.crc, true);
        h.setUint32(20, e.csize, true);
        h.setUint32(24, e.size, true);
        h.setUint16(28, e.nameBytes.length, true);
        h.setUint32(42, e.offset, true);
        this.put(new Uint8Array(h.buffer));
        this.put(e.nameBytes);
      }
      const end = new DataView(new ArrayBuffer(22));
      end.setUint32(0, 0x06054b50, true);
      end.setUint16(8, this.entries.length, true);
      end.setUint16(10, this.entries.length, true);
      end.setUint32(12, this.offset - cdStart, true);
      end.setUint32(16, cdStart, true);
      this.put(new Uint8Array(end.buffer));
    }
  }

  // ---------------------------------------------------------------------
  // Streaming .xlsx writer. Inline strings (no shared-string table) keep
  // memory flat; sheets roll over at Excel's row limit.
  // ---------------------------------------------------------------------
  const XLSX_MIME = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
  const XLSX_MAX_ROWS = 1048575;        // data rows per sheet, plus the header row
  const XLSX_MAX_CELL = 32767;          // Excel's per-cell character limit
  const XLSX_SHEET_CHARS = 1.2e9;       // keeps each sheet's XML well under 4 GB
  const BAD_XML_CHARS = /[\x00-\x08\x0B\x0C\x0E-\x1F￾￿]/g;
  const XML_SPECIAL = /[&<>\x00-\x08\x0B\x0C\x0E-\x1F￾￿]/;
  const NUMERIC = /^-?(?:0|[1-9]\d{0,14})(?:\.\d{1,10})?$/;
  const NEW_SHEET = {};
  const NS_MAIN = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main';
  const NS_REL = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships';
  const XML_DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n';
  const COLUMN_WIDTHS = {
    'plugin id': 10, 'cve': 16, 'risk': 9, 'host': 18, 'protocol': 9, 'port': 7, 'name': 45,
    'synopsis': 45, 'description': 60, 'solution': 45, 'see also': 35, 'plugin output': 60,
    'ip address': 15, 'fqdn': 28, 'os': 30, 'source file': 30, 'plugin family': 22, 'scan name': 24,
  };

  function colLetter(i) {
    let s = '';
    for (i++; i > 0; i = Math.floor((i - 1) / 26)) s = String.fromCharCode(65 + ((i - 1) % 26)) + s;
    return s;
  }

  function xmlEscape(s) {
    if (!XML_SPECIAL.test(s)) return s;
    return s.replace(BAD_XML_CHARS, '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  class XlsxOutput {
    constructor(sink, cols) {
      this.sink = sink;
      this.zip = new ZipWriter(sink);
      this.mime = XLSX_MIME;
      this.cols = cols;
      this.letters = cols.map((_, i) => colLetter(i));
      this.queue = [];          // row XML and NEW_SHEET markers awaiting flush()
      this.pending = '';
      this.pendingLen = 0;
      this.sheetRows = [0];     // data rows per sheet
      this.sheetChars = 0;
      this.stream = null;
      this.truncated = 0;
    }

    cellXml(v, ref, style) {
      if (v === undefined || v === '') return '';
      if (NUMERIC.test(v) && !style) return `<c r="${ref}"><v>${v}</v></c>`;
      if (v.length > XLSX_MAX_CELL) {
        v = v.slice(0, XLSX_MAX_CELL - 12) + ' [truncated]';
        this.truncated++;
      }
      return `<c r="${ref}"${style ? ' s="1"' : ''} t="inlineStr"><is><t xml:space="preserve">${xmlEscape(v)}</t></is></c>`;
    }

    rowXml(values, r, style) {
      let xml = `<row r="${r}">`;
      for (let i = 0; i < values.length; i++) xml += this.cellXml(values[i], this.letters[i] + r, style);
      return xml + '</row>';
    }

    row(values) {
      const n = this.sheetRows.length - 1;
      if (this.sheetRows[n] >= XLSX_MAX_ROWS || this.sheetChars >= XLSX_SHEET_CHARS) {
        this.queue.push(this.pending, NEW_SHEET);
        this.pending = '';
        this.sheetRows.push(0);
        this.sheetChars = 0;
      }
      const sheet = this.sheetRows.length - 1;
      const xml = this.rowXml(values, ++this.sheetRows[sheet] + 1, false);
      this.pending += xml;
      this.pendingLen += xml.length;
      this.sheetChars += xml.length;
    }

    get needsFlush() { return this.pendingLen >= FLUSH_SIZE || this.sink.needsFlush; }

    sheetName(i) { return i === 0 ? 'Findings' : `Findings (${i + 1})`; }

    async beginSheet() {
      const i = this.stream ? this.stream.index + 1 : 0;
      const stream = this.zip.openStream(`xl/worksheets/sheet${i + 1}.xml`);
      stream.index = i;
      this.stream = stream;
      const cols = this.cols.map((c, j) =>
        `<col min="${j + 1}" max="${j + 1}" width="${COLUMN_WIDTHS[c.toLowerCase()] || 16}" customWidth="1"/>`).join('');
      await stream.write(
        XML_DECL + `<worksheet xmlns="${NS_MAIN}" xmlns:r="${NS_REL}">` +
        `<sheetViews><sheetView workbookViewId="0"${i === 0 ? ' tabSelected="1"' : ''}>` +
        '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>' +
        '<selection pane="bottomLeft" activeCell="A2" sqref="A2"/></sheetView></sheetViews>' +
        `<sheetFormatPr defaultRowHeight="15"/><cols>${cols}</cols><sheetData>` +
        this.rowXml(this.cols, 1, true));
    }

    async endSheet() {
      const i = this.stream.index;
      const last = this.letters[this.letters.length - 1] + (this.sheetRows[i] + 1);
      await this.stream.write(`</sheetData><autoFilter ref="A1:${last}"/></worksheet>`);
      await this.stream.close();
    }

    async flush() {
      const ops = this.queue;
      ops.push(this.pending);
      this.queue = [];
      this.pending = '';
      this.pendingLen = 0;
      if (!this.stream) await this.beginSheet();
      for (const op of ops) {
        if (op === NEW_SHEET) { await this.endSheet(); await this.beginSheet(); }
        else if (op) await this.stream.write(op);
      }
      await this.sink.flush();
    }

    async finish() {
      await this.flush();
      await this.endSheet();
      const n = this.sheetRows.length;
      const lastCol = this.letters[this.letters.length - 1];
      const idx = [...Array(n).keys()];
      const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

      this.zip.addFile('[Content_Types].xml', XML_DECL +
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' +
        '<Default Extension="xml" ContentType="application/xml"/>' +
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>' +
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>' +
        idx.map(i => `<Override PartName="/xl/worksheets/sheet${i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`).join('') +
        '</Types>');
      this.zip.addFile('_rels/.rels', XML_DECL +
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
        `<Relationship Id="rId1" Type="${NS_REL}/officeDocument" Target="xl/workbook.xml"/></Relationships>`);
      this.zip.addFile('xl/workbook.xml', XML_DECL +
        `<workbook xmlns="${NS_MAIN}" xmlns:r="${NS_REL}"><bookViews><workbookView/></bookViews><sheets>` +
        idx.map(i => `<sheet name="${esc(this.sheetName(i))}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`).join('') +
        '</sheets><definedNames>' +
        idx.map(i => `<definedName name="_xlnm._FilterDatabase" localSheetId="${i}" hidden="1">` +
          `${esc(`'${this.sheetName(i)}'`)}!$A$1:$${lastCol}$${this.sheetRows[i] + 1}</definedName>`).join('') +
        '</definedNames></workbook>');
      this.zip.addFile('xl/_rels/workbook.xml.rels', XML_DECL +
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
        idx.map(i => `<Relationship Id="rId${i + 1}" Type="${NS_REL}/worksheet" Target="worksheets/sheet${i + 1}.xml"/>`).join('') +
        `<Relationship Id="rId${n + 1}" Type="${NS_REL}/styles" Target="styles.xml"/></Relationships>`);
      this.zip.addFile('xl/styles.xml', XML_DECL +
        `<styleSheet xmlns="${NS_MAIN}">` +
        '<fonts count="2"><font><sz val="11"/><name val="Calibri"/><family val="2"/></font>' +
        '<font><b/><sz val="11"/><name val="Calibri"/><family val="2"/></font></fonts>' +
        '<fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill>' +
        '<fill><patternFill patternType="solid"><fgColor rgb="FFD9E1F2"/><bgColor indexed="64"/></patternFill></fill></fills>' +
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>' +
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>' +
        '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>' +
        '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/></cellXfs>' +
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>');
      this.zip.finish();
      return { sheets: n, truncatedCells: this.truncated };
    }
  }

  // ---------------------------------------------------------------------
  // Merge
  // ---------------------------------------------------------------------
  let cancelled = false;

  async function merge(msg) {
    cancelled = false;
    const { sources, columns, options, outputHandle } = msg;
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
    if (options.format === 'xlsx' && typeof CompressionStream !== 'function') {
      throw new Error('This browser cannot create .xlsx files. Use a current Chrome, Edge, Firefox or Safari, or choose CSV output.');
    }
    const out = options.format === 'xlsx' ? new XlsxOutput(sink, outCols) : new CsvOutput(sink, outCols, options.bom);

    const totalBytes = sources.reduce((s, src) => s + sourceBytes(src), 0);
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
      for (let fi = 0; fi < sources.length; fi++) {
        if (cancelled) break;
        const src = sources[fi];
        const stats = { rowsIn: 0, rowsOut: 0, duplicates: 0, filtered: 0, excluded: 0, malformed: 0, error: null };
        let map = null;        // source column index -> output column index (or -1)
        let fileCols = 0;
        // Key columns come from the source itself so dedupe/filter still work
        // when the user has deselected those columns from the output.
        let fKey = null;
        let fRules = null;     // rules whose column exists in this source
        const blank = new Array(outCols.length);

        const setHeaders = headers => {
          fileCols = headers.length;
          map = headers.map(h => {
            const idx = outColIndex.get(h.toLowerCase());
            return idx === undefined || idx === sourceIdx ? -1 : idx;
          });
          fKey = {};
          for (const k of Object.keys(KEY_ALIASES)) fKey[k] = findColumn(headers, KEY_ALIASES[k]);
          const lower = headers.map(h => h.toLowerCase());
          fRules = rules.map(r => ({ ...r, col: lower.indexOf(r.key) })).filter(r => r.col !== -1);
        };

        const handleRow = row => {
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

          const values = blank.slice();
          for (let i = 0; i < row.length && i < map.length; i++) {
            const o = map[i];
            if (o !== -1) values[o] = row[i];
          }
          if (sourceIdx !== -1) values[sourceIdx] = src.name;
          out.row(values);
          stats.rowsOut++;

          if (fKey.host !== -1) {
            const h = row[fKey.host];
            if (h) hosts.add(h.trim());
          }
          if (fKey.risk !== -1) {
            const s = (row[fKey.risk] || '').trim() || 'Unspecified';
            severity[s] = (severity[s] || 0) + 1;
          }
        };

        let parser;
        if (src.kind === 'nessus') {
          setHeaders(NESSUS_COLUMNS);
          parser = new NessusStreamParser(handleRow);
        } else {
          parser = new CsvStreamParser(row => {
            if (map === null) setHeaders(row.map(normalizeHeader));
            else handleRow(row);
          });
        }

        let consumed = 0;
        try {
          for await (const { text, bytes } of textChunks(src)) {
            if (cancelled) break;
            parser.push(text);
            consumed += bytes;
            bytesDone += bytes;
            if (out.needsFlush) await out.flush();
            const now = Date.now();
            if (now - lastProgress > PROGRESS_INTERVAL_MS) {
              lastProgress = now;
              self.postMessage({
                type: 'progress', fileIndex: fi, bytesDone, totalBytes,
                rowsOut: totals.rowsOut + stats.rowsOut,
              });
            }
          }
          if (!cancelled) parser.end();
        } catch (err) {
          // Output errors (e.g. size limits) abort the whole merge; input
          // errors only skip the rest of this source.
          if (err && err.message === ZIP_TOO_BIG) throw err;
          stats.error = String(err && err.message || err);
        }
        bytesDone += sourceBytes(src) - consumed; // keep progress exact if a source stopped early

        await out.flush();
        for (const k of Object.keys(totals)) totals[k] += stats[k];
        perFile.push(stats);
        self.postMessage({ type: 'fileDone', fileIndex: fi, stats });
      }

      if (cancelled) {
        await sink.abort();
        self.postMessage({ type: 'cancelled' });
        return;
      }

      const extra = await out.finish();
      const blob = await sink.close(out.mime);
      self.postMessage({
        type: 'done',
        blob,
        stats: {
          ...totals,
          ...extra,
          format: options.format,
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
            self.postMessage({ type: 'scanResult', id, ...(await scanFile(file)) });
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
  self.__mergeInternals = { CsvStreamParser, NessusStreamParser, HashSet64, hash64, compileRules, listZip, scanFile, crc32 };
}
