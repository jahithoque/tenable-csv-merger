/*
 * Merge engine. Everything lives inside mergeWorkerMain so app.js can
 * serialise it into a Blob-URL worker \u2014 that keeps the app working when
 * index.html is opened straight from disk (file://), where
 * `new Worker('merge-worker.js')` would be blocked.
 */
function mergeWorkerMain() {
  'use strict';

  // Must match APP_VERSION in app.js; the page warns when files are mixed.
  const WORKER_VERSION = '2026.10.12-3';

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
    check: ['compliance check', 'compliance check name', 'check name'],
    result: ['compliance result', 'compliance status'],
    audit: ['compliance audit file', 'audit file'],
    name: ['name', 'plugin name'],
    family: ['plugin family', 'family'],
    ip: ['ip address', 'host-ip', 'ip'],
    fqdn: ['fqdn', 'dns name', 'host-fqdn'],
    os: ['os', 'operating system', 'operating-system'],
    desc: ['description'],
    output: ['plugin output', 'output'],
    service: ['service', 'svc_name'],
  };
  const INFO_LEVELS = new Set(['none', 'info', 'informational']);

  // Compliance checks put "<check name>": [RESULT] at the start of their
  // description, in both .nessus files and Tenable's CSV export.
  const COMPLIANCE_DESC_RE = /^\s*(?:"([^"\n]{1,2000})"|([^\n:"]{1,2000}?))\s*:\s*\[(PASSED|FAILED|WARNING|ERROR|SKIPPED|INFO|N\/A)\]/i;
  const DERIVED_COLUMNS = ['Compliance Check', 'Compliance Result'];

  function parseComplianceDesc(desc) {
    if (!desc || desc.indexOf('[') === -1) return null;
    const m = COMPLIANCE_DESC_RE.exec(desc.length > 2100 ? desc.slice(0, 2100) : desc);
    return m ? [(m[1] || m[2]).trim(), m[3].toUpperCase()] : null;
  }

  // Buckets: 0 passed, 1 failed, 2 warning, 3 other (error, skipped, \u2026).
  function complianceBucket(result) {
    const r = result.trim().toUpperCase();
    if (!r) return -1;
    if (r === 'PASSED' || r === 'PASS') return 0;
    if (r === 'FAILED' || r === 'FAIL') return 1;
    if (r === 'WARNING' || r === 'WARN') return 2;
    return 3;
  }

  // Tenable compliance exports often carry the result only in Risk:
  // None = passed, High = failed, Medium = warning / manual check.
  function riskToResult(risk) {
    const r = risk.trim().toLowerCase();
    if (INFO_LEVELS.has(r) || r === 'passed') return 'PASSED';
    if (r === 'high' || r === 'critical') return 'FAILED';
    if (r === 'medium' || r === 'low') return 'WARNING';
    return '';
  }

  // Credential failure plugins (e.g. 104410) list each failed login as
  // "Protocol : SMB / Port : 445 / User : 'admin' / Error : \u2026" blocks.
  const AUTH_FIELDS = ['protocol', 'port', 'user', 'domain', 'error'];
  function parseAuthOutput(text) {
    const found = { protocol: new Set(), port: new Set(), user: new Set(), domain: new Set(), error: new Set() };
    const re = /^[ \t]*(Protocol|Port|User(?:name)?|Domain|Error|Message)[ \t]*:[ \t]*(.+)$/gim;
    let m;
    while ((m = re.exec(text))) {
      let key = m[1].toLowerCase();
      if (key === 'username') key = 'user';
      if (key === 'message') key = 'error';
      const v = m[2].trim().replace(/^'(.*)'$/, '$1');
      if (v && found[key].size < 20) found[key].add(v);
    }
    const out = {};
    for (const k of AUTH_FIELDS) out[k] = [...found[k]].join('; ');
    return out;
  }

  // Buckets: 0 critical, 1 high, 2 medium, 3 low, 4 info, 5 other.
  function severityBucket(risk) {
    const r = risk.trim().toLowerCase();
    if (r === 'critical') return 0;
    if (r === 'high') return 1;
    if (r === 'medium') return 2;
    if (r === 'low') return 3;
    if (INFO_LEVELS.has(r)) return 4;
    return 5;
  }

  function normalizeHeader(h) {
    return h.replace(/^\uFEFF/, '').trim();
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

  // Yields { text, bytes } \u2014 decoded text plus how many bytes of the input
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
  // export \u2014 one row per CVE \u2014 so they merge cleanly with CSV reports.
  // ---------------------------------------------------------------------
  const NESSUS_COLUMNS = [
    'Plugin ID', 'CVE', 'CVSS v2.0 Base Score', 'Risk', 'Host', 'Protocol', 'Port', 'Name',
    'Synopsis', 'Description', 'Solution', 'See Also', 'Plugin Output',
    'CVSS v3.0 Base Score', 'CVSS v4.0 Base Score', 'VPR Score', 'EPSS Score', 'STIG Severity',
    'BID', 'XREF', 'MSKB', 'Plugin Publication Date', 'Plugin Modification Date', 'Patch Publication Date',
    'Exploit Available', 'Metasploit', 'Core Impact', 'CANVAS', 'Plugin Family', 'Service',
    'IP Address', 'FQDN', 'NetBIOS Name', 'OS', 'MAC Address', 'Scan Name', 'Scan Start', 'Scan End',
    'Compliance Check', 'Compliance Result', 'Compliance Actual Value', 'Compliance Policy Value',
    'Compliance Reference', 'Compliance Audit File',
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
      let check = one('cm:compliance-check-name');
      let result = one('cm:compliance-result');
      if (!result) {
        const parsed = parseComplianceDesc(one('description'));
        if (parsed) { check = check || parsed[0]; result = parsed[1]; }
      }
      row.push(check, result, one('cm:compliance-actual-value'), one('cm:compliance-policy-value'),
        one('cm:compliance-reference'), one('cm:compliance-audit-file'));
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

  // Reads just enough of a source to learn its columns and whether it holds
  // compliance results. CSVs with compliance rows but no result column get
  // two derived columns parsed from Description.
  async function probe(src) {
    if (src.kind === 'csv') {
      let headers = null;
      let descIdx = -1;
      let compliance = false;
      const parser = new CsvStreamParser(row => {
        if (!headers) {
          headers = row.map(normalizeHeader);
          descIdx = findColumn(headers, KEY_ALIASES.desc);
          return descIdx !== -1;
        }
        if (parseComplianceDesc(row[descIdx] || '')) { compliance = true; return false; }
      });
      let read = 0;
      for await (const { text, bytes } of textChunks(src, PROBE_CHUNK)) {
        parser.push(text);
        read += bytes;
        if (parser.stopped || read >= 2 * PROBE_CHUNK) break;
      }
      if (!headers) parser.end();
      if (!headers) throw new Error('File is empty or has no header row');
      const hasResult = findColumn(headers, KEY_ALIASES.result) !== -1;
      const derive = compliance && !hasResult && descIdx !== -1;
      if (derive) headers = headers.concat(DERIVED_COLUMNS);
      return { headers, ...describeFile(headers), compliance: compliance || hasResult, derive };
    }
    let head = '';
    for await (const { text } of textChunks(src, PROBE_CHUNK)) {
      head += text;
      if (head.length >= 1024 * 1024) break;
    }
    if (!/<NessusClientData_v2[\s>]/.test(head)) throw new Error('Not a .nessus (NessusClientData_v2) file');
    return { headers: NESSUS_COLUMNS.slice(), recognized: true, compliance: /cm:compliance-|\.audit\b/.test(head) };
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
  // Writing \u2014 straight to disk via the File System Access API when the
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
      if (bom) sink.append('\uFEFF');
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
  const XLSX_SHEET_BYTES = 4.0e9;       // a sheet's XML must stay under the 4 GB ZIP entry limit
  const BAD_XML_CHARS = /[\x00-\x08\x0B\x0C\x0E-\x1F\uFFFE\uFFFF]/g;
  const XML_SPECIAL = /[&<>\x00-\x08\x0B\x0C\x0E-\x1F\uFFFE\uFFFF]/;
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

  // UTF-8 byte length without encoding (surrogate pairs: 2 units -> 4 bytes).
  function utf8Length(s) {
    let n = s.length;
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (c > 0x7f) n += c <= 0x7ff || (c >= 0xd800 && c <= 0xdfff) ? 1 : 2;
    }
    return n;
  }

  // Wrapped lines needed to show text in a column `width` characters wide.
  function wrappedLines(text, width) {
    let lines = 0;
    for (const part of text.split('\n')) lines += Math.max(1, Math.ceil(part.length / Math.max(width, 4)));
    return lines;
  }

  // Two lines of 10pt Arial, so a compact findings row shows the start of
  // the description without a cut-off third line.
  const COMPACT_ROW_HEIGHT = 26;

  const findingsSheetName = i => (i === 0 ? 'Findings' : `Findings (${i + 1})`);

  function colLetter(i) {
    let s = '';
    for (i++; i > 0; i = Math.floor((i - 1) / 26)) s = String.fromCharCode(65 + ((i - 1) % 26)) + s;
    return s;
  }

  function xmlEscape(s) {
    if (!XML_SPECIAL.test(s)) return s;
    return s.replace(BAD_XML_CHARS, '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // Cell style indices; must match the xfs list in stylesXml.
  const ST = {
    header: 1, title: 2, bold: 3, pct: 4, note: 5,
    critical: 6, high: 7, medium: 8, low: 9, info: 10,
    passed: 11, failed: 12, warning: 13, other: 14, section: 15,
    td: 16, tdNum: 17, tdBold: 18, tdNumBold: 19, tdPct: 20,
    kpiValue: 21, kpiLabel: 22, kpiBad: 23, kpiGood: 24, kpiPct: 25, subtitle: 26,
    cellText: 27, cellNum: 28,
  };
  const SEVERITIES = [
    ['Critical', ST.critical, '91243E'], ['High', ST.high, 'DD4B50'], ['Medium', ST.medium, 'F18C43'],
    ['Low', ST.low, 'F8C851'], ['Info', ST.info, '67ACE1'], ['Other', ST.other, 'A6A6A6'],
  ];
  const COMPLIANCE_RESULTS = [
    ['Passed', ST.passed, '2E9E5B'], ['Failed', ST.failed, 'C23B3B'],
    ['Warning / Manual check', ST.warning, 'F0A030'], ['Error / other', ST.other, 'A6A6A6'],
  ];

  function stylesXml() {
    // Arial rather than Calibri: Excel for Mac can draw Calibri with almost
    // zero-width spaces ("% of checks" reads "%ofchecks"), and Arial is
    // installed on every Mac and Windows machine.
    const font = (flags = '', size = 10, color = '') =>
      `<font>${flags}<sz val="${size}"/>${color ? `<color rgb="FF${color}"/>` : ''}<name val="Arial"/><family val="2"/></font>`;
    // 0 normal, 1 bold, 2 title, 3 note, 4 bold white, 5 section, 6 KPI value,
    // 7 KPI label, 8 KPI value (bad), 9 KPI value (good)
    const fonts = [font(), font('<b/>'), font('<b/>', 16, '1F3864'), font('<i/>', 9, '666666'),
      font('<b/>', 10, 'FFFFFF'), font('<b/>', 11, '1F3864'), font('<b/>', 18, '1F3864'),
      font('', 9, '595959'), font('<b/>', 18, 'C23B3B'), font('<b/>', 18, '2E9E5B')];
    const solid = rgb => `<fill><patternFill patternType="solid"><fgColor rgb="FF${rgb}"/><bgColor indexed="64"/></patternFill></fill>`;
    const fills = ['<fill><patternFill patternType="none"/></fill>', '<fill><patternFill patternType="gray125"/></fill>',
      solid('D9E1F2'), solid('91243E'), solid('DD4B50'), solid('F18C43'), solid('F8C851'), solid('67ACE1'),
      solid('2E9E5B'), solid('C23B3B'), solid('F0A030'), solid('D9D9D9'), solid('F2F5FA')];
    const side = (name, rgb) => (rgb ? `<${name} style="thin"><color rgb="FF${rgb}"/></${name}>` : `<${name}/>`);
    const border = (l, r, t, b, rgb) =>
      `<border>${side('left', l && rgb)}${side('right', r && rgb)}${side('top', t && rgb)}${side('bottom', b && rgb)}<diagonal/></border>`;
    // 0 none, 1 table grid, 2 KPI tile top half, 3 KPI tile bottom half
    const borders = [border(0, 0, 0, 0), border(1, 1, 1, 1, 'BFBFBF'), border(1, 1, 1, 0, 'B4C6E7'), border(1, 1, 0, 1, 'B4C6E7')];
    const xf = ({ font = 0, fill = 0, num = 0, bd = 0, h = '', v = 'center', wrap = false, indent = 0 } = {}) =>
      `<xf numFmtId="${num}" fontId="${font}" fillId="${fill}" borderId="${bd}" xfId="0"` +
      `${font ? ' applyFont="1"' : ''}${fill ? ' applyFill="1"' : ''}${num ? ' applyNumberFormat="1"' : ''}` +
      `${bd ? ' applyBorder="1"' : ''} applyAlignment="1"><alignment${h ? ` horizontal="${h}"` : ''} vertical="${v}"` +
      `${indent ? ` indent="${indent}"` : ''}${wrap ? ' wrapText="1"' : ''}/></xf>`;
    const label = (font, fill) => xf({ font, fill, bd: 1, h: 'center' });
    const xfs = [
      xf({ v: 'bottom' }),                                              // 0 default
      xf({ font: 1, fill: 2, bd: 1, h: 'center', wrap: true }),         // 1 header
      xf({ font: 2, h: 'center' }),                                     // 2 title
      xf({ font: 1 }),                                                  // 3 bold
      xf({ num: 10, h: 'center' }),                                     // 4 pct
      xf({ font: 3, h: 'left', wrap: true, indent: 1 }),                // 5 note
      label(4, 3), label(4, 4), label(4, 5), label(1, 6), label(1, 7),  // 6-10 severity labels
      label(4, 8), label(4, 9), label(1, 10), label(1, 11),             // 11-14 compliance labels
      xf({ font: 5, v: 'bottom' }),                                     // 15 section heading
      xf({ bd: 1, h: 'left', wrap: true, indent: 1 }),                  // 16 table text
      xf({ bd: 1, h: 'center' }),                                       // 17 table number
      xf({ font: 1, bd: 1, h: 'left', indent: 1 }),                     // 18 table text, bold
      xf({ font: 1, bd: 1, h: 'center' }),                              // 19 table number, bold
      xf({ num: 10, bd: 1, h: 'center' }),                              // 20 table percent
      xf({ font: 6, fill: 12, bd: 2, h: 'center' }),                    // 21 KPI value
      xf({ font: 7, fill: 12, bd: 3, h: 'center', v: 'top', wrap: true }), // 22 KPI label
      xf({ font: 8, fill: 12, bd: 2, h: 'center' }),                    // 23 KPI value, bad
      xf({ font: 9, fill: 12, bd: 2, h: 'center' }),                    // 24 KPI value, good
      xf({ font: 6, fill: 12, bd: 2, h: 'center', num: 10 }),           // 25 KPI percent
      xf({ font: 3, h: 'center' }),                                     // 26 subtitle
      // Findings cells wrap so embedded line breaks render as breaks (unwrapped,
      // Excel draws them as nothing and glues words together). Top-aligned so
      // a compact row shows the first line.
      xf({ bd: 1, h: 'left', v: 'top', wrap: true, indent: 1 }),       // 27 findings text
      xf({ bd: 1, h: 'center', v: 'top' }),                             // 28 findings number
    ];
    return XML_DECL + `<styleSheet xmlns="${NS_MAIN}">` +
      `<fonts count="${fonts.length}">${fonts.join('')}</fonts>` +
      `<fills count="${fills.length}">${fills.join('')}</fills>` +
      `<borders count="${borders.length}">${borders.join('')}</borders>` +
      '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>' +
      `<cellXfs count="${xfs.length}">${xfs.join('')}</cellXfs>` +
      '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>';
  }

  const escAttr = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

  // DrawingML chart: { type: 'bar' | 'doughnut', title, sheet, catRange, valRange, cats, vals, colors }
  function chartXml(c) {
    const ref = r => `'${c.sheet}'!${r}`;
    const pts = (arr, num) => `<c:ptCount val="${arr.length}"/>` +
      arr.map((v, i) => `<c:pt idx="${i}"><c:v>${num ? v : xmlEscape(String(v))}</c:v></c:pt>`).join('');
    const dPts = c.colors.map((rgb, i) =>
      `<c:dPt><c:idx val="${i}"/>${c.type === 'bar' ? '<c:invertIfNegative val="0"/>' : ''}<c:bubble3D val="0"/>` +
      `<c:spPr><a:solidFill><a:srgbClr val="${rgb}"/></a:solidFill></c:spPr></c:dPt>`).join('');
    // No label on empty doughnut slices (Excel would print "0%").
    const hideZero = c.type === 'bar' ? '' : c.vals.map((v, i) => (v ? '' : `<c:dLbl><c:idx val="${i}"/><c:delete val="1"/></c:dLbl>`)).join('');
    const labels = `<c:dLbls>${hideZero}<c:showLegendKey val="0"/><c:showVal val="${c.type === 'bar' ? 1 : 0}"/>` +
      `<c:showCatName val="0"/><c:showSerName val="0"/><c:showPercent val="${c.type === 'bar' ? 0 : 1}"/>` +
      '<c:showBubbleSize val="0"/></c:dLbls>';
    const ser = '<c:ser><c:idx val="0"/><c:order val="0"/><c:tx><c:v>Count</c:v></c:tx>' +
      (c.type === 'bar' ? '<c:invertIfNegative val="0"/>' : '') + dPts + labels +
      `<c:cat><c:strRef><c:f>${ref(c.catRange)}</c:f><c:strCache>${pts(c.cats, false)}</c:strCache></c:strRef></c:cat>` +
      `<c:val><c:numRef><c:f>${ref(c.valRange)}</c:f><c:numCache><c:formatCode>General</c:formatCode>${pts(c.vals, true)}</c:numCache></c:numRef></c:val></c:ser>`;
    const plot = c.type === 'bar'
      ? '<c:barChart><c:barDir val="col"/><c:grouping val="clustered"/><c:varyColors val="0"/>' + ser +
        '<c:gapWidth val="60"/><c:axId val="5001"/><c:axId val="5002"/></c:barChart>' +
        '<c:catAx><c:axId val="5001"/><c:scaling><c:orientation val="minMax"/></c:scaling><c:delete val="0"/>' +
        '<c:axPos val="b"/><c:numFmt formatCode="General" sourceLinked="0"/><c:majorTickMark val="none"/>' +
        '<c:minorTickMark val="none"/><c:tickLblPos val="nextTo"/><c:crossAx val="5002"/><c:crosses val="autoZero"/>' +
        '<c:auto val="1"/><c:lblAlgn val="ctr"/><c:lblOffset val="100"/><c:noMultiLvlLbl val="0"/></c:catAx>' +
        '<c:valAx><c:axId val="5002"/><c:scaling><c:orientation val="minMax"/></c:scaling><c:delete val="0"/>' +
        '<c:axPos val="l"/><c:majorGridlines><c:spPr><a:ln w="6350"><a:solidFill><a:srgbClr val="D9D9D9"/></a:solidFill></a:ln></c:spPr></c:majorGridlines>' +
        '<c:numFmt formatCode="General" sourceLinked="1"/>' +
        '<c:majorTickMark val="none"/><c:minorTickMark val="none"/><c:tickLblPos val="nextTo"/>' +
        '<c:crossAx val="5001"/><c:crosses val="autoZero"/><c:crossBetween val="between"/></c:valAx>'
      : '<c:doughnutChart><c:varyColors val="1"/>' + ser + '<c:firstSliceAng val="0"/><c:holeSize val="55"/></c:doughnutChart>';
    return XML_DECL +
      '<c:chartSpace xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" ' +
      `xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="${NS_REL}">` +
      '<c:roundedCorners val="0"/><c:chart>' +
      '<c:title><c:tx><c:rich><a:bodyPr/><a:p><a:pPr><a:defRPr sz="1200" b="1"/></a:pPr>' +
      `<a:r><a:rPr lang="en-US" sz="1200" b="1"><a:latin typeface="Arial"/></a:rPr><a:t>${xmlEscape(c.title)}</a:t></a:r></a:p></c:rich></c:tx>` +
      '<c:overlay val="0"/></c:title><c:autoTitleDeleted val="0"/>' +
      `<c:plotArea><c:layout/>${plot}</c:plotArea>` +
      (c.type === 'bar' ? '' : '<c:legend><c:legendPos val="r"/><c:overlay val="0"/></c:legend>') +
      '<c:plotVisOnly val="1"/><c:dispBlanksAs val="gap"/></c:chart>' +
      '<c:txPr><a:bodyPr/><a:lstStyle/><a:p><a:pPr><a:defRPr sz="900"><a:latin typeface="Arial"/></a:defRPr></a:pPr>' +
      '<a:endParaRPr lang="en-US"/></a:p></c:txPr></c:chartSpace>';
  }

  function drawingXml(anchors) {
    return XML_DECL +
      '<xdr:wsDr xmlns:xdr="http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing" ' +
      'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">' +
      anchors.map((an, i) =>
        '<xdr:twoCellAnchor editAs="oneCell">' +
        `<xdr:from><xdr:col>${an.from[0]}</xdr:col><xdr:colOff>0</xdr:colOff><xdr:row>${an.from[1]}</xdr:row><xdr:rowOff>0</xdr:rowOff></xdr:from>` +
        `<xdr:to><xdr:col>${an.to[0]}</xdr:col><xdr:colOff>0</xdr:colOff><xdr:row>${an.to[1]}</xdr:row><xdr:rowOff>0</xdr:rowOff></xdr:to>` +
        `<xdr:graphicFrame macro=""><xdr:nvGraphicFramePr><xdr:cNvPr id="${i + 2}" name="Chart ${i + 1}"/><xdr:cNvGraphicFramePr/></xdr:nvGraphicFramePr>` +
        '<xdr:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/></xdr:xfrm>' +
        '<a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/chart">' +
        `<c:chart xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" xmlns:r="${NS_REL}" r:id="rId${i + 1}"/>` +
        '</a:graphicData></a:graphic></xdr:graphicFrame><xdr:clientData/></xdr:twoCellAnchor>').join('') +
      '</xdr:wsDr>';
  }

  class XlsxOutput {
    constructor(sink, cols, withSummary, fitRows) {
      this.sink = sink;
      this.fitRows = fitRows;   // true: let Excel size rows to the full text
      this.zip = new ZipWriter(sink);
      this.mime = XLSX_MIME;
      this.cols = cols;
      this.withSummary = withSummary;
      this.letters = cols.map((_, i) => colLetter(i));
      this.queue = [];          // row XML and NEW_SHEET markers awaiting flush()
      this.pending = '';
      this.pendingLen = 0;
      this.sheetRows = [0];     // data rows per findings sheet
      this.sheetBytes = 0;
      this.stream = null;
      this.truncated = 0;
    }

    cellXml(v, ref, style) {
      if (v === undefined || v === '') return style ? '' : `<c r="${ref}" s="${ST.cellText}"/>`;
      if (NUMERIC.test(v) && !style) return `<c r="${ref}" s="${ST.cellNum}"><v>${v}</v></c>`;
      if (!style) style = ST.cellText;
      if (v.length > XLSX_MAX_CELL) {
        v = v.slice(0, XLSX_MAX_CELL - 12) + ' [truncated]';
        this.truncated++;
      }
      return `<c r="${ref}"${style ? ` s="${style}"` : ''} t="inlineStr"><is><t xml:space="preserve">${xmlEscape(v)}</t></is></c>`;
    }

    // Compact findings rows get an explicit height; otherwise Excel auto-fits
    // every wrapped row to its full text.
    rowXml(values, r, style, height = this.fitRows ? 0 : COMPACT_ROW_HEIGHT) {
      let xml = `<row r="${r}"${height ? ` ht="${height}" customHeight="1"` : ''}>`;
      for (let i = 0; i < values.length; i++) xml += this.cellXml(values[i], this.letters[i] + r, style);
      return xml + '</row>';
    }

    // A new sheet starts only at Excel's row limit or when this sheet's XML
    // would pass the 4 GB ZIP entry limit.
    row(values) {
      let n = this.sheetRows.length - 1;
      const truncatedBefore = this.truncated;
      let xml = this.rowXml(values, this.sheetRows[n] + 2, 0);
      let bytes = utf8Length(xml);
      if (this.sheetRows[n] >= XLSX_MAX_ROWS || this.sheetBytes + bytes > XLSX_SHEET_BYTES) {
        this.queue.push(this.pending, NEW_SHEET);
        this.pending = '';
        this.sheetRows.push(0);
        this.sheetBytes = 0;
        n++;
        this.truncated = truncatedBefore;
        xml = this.rowXml(values, 2, 0); // row numbers restart on the new sheet
        bytes = utf8Length(xml);
      }
      this.sheetRows[n]++;
      this.pending += xml;
      this.pendingLen += xml.length;
      this.sheetBytes += bytes;
    }

    get currentSheet() { return this.sheetRows.length - 1; }

    get needsFlush() { return this.pendingLen >= FLUSH_SIZE || this.sink.needsFlush; }

    sheetName(i) { return findingsSheetName(i); }

    sheetHead({ widths, freeze, selected, gridlines = true, print = false, rowHeight = 20, fit = false }) {
      const cols = widths.map((w, j) => `<col min="${j + 1}" max="${j + 1}" width="${w}" customWidth="1"/>`).join('');
      return XML_DECL + `<worksheet xmlns="${NS_MAIN}" xmlns:r="${NS_REL}">` +
        (print ? '<sheetPr><pageSetUpPr fitToPage="1"/></sheetPr>' : '') +
        `<sheetViews><sheetView workbookViewId="0"${gridlines ? '' : ' showGridLines="0"'}${selected ? ' tabSelected="1"' : ''}>` +
        (freeze
          ? '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/><selection pane="bottomLeft" activeCell="A2" sqref="A2"/>'
          : '<selection activeCell="A1" sqref="A1"/>') +
        `</sheetView></sheetViews>` +
        (fit ? '<sheetFormatPr defaultRowHeight="15"/>' : `<sheetFormatPr defaultRowHeight="${rowHeight}" customHeight="1"/>`) +
        `${cols ? `<cols>${cols}</cols>` : ''}<sheetData>`;
    }

    async beginSheet() {
      const i = this.stream ? this.stream.index + 1 : 0;
      const stream = this.zip.openStream(`xl/worksheets/sheet${i + 1}.xml`);
      stream.index = i;
      this.stream = stream;
      const widths = this.cols.map(c => COLUMN_WIDTHS[c.toLowerCase()] || 16);
      await stream.write(this.sheetHead({ widths, freeze: true, selected: i === 0 && !this.withSummary, fit: this.fitRows }) +
        this.rowXml(this.cols, 1, ST.header, 24));
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

    // Writes a summary sheet described as { name, widths, rows, freeze, filter, charts }.
    // Cells are strings, numbers, null, or { v, s } with a style index.
    async writeSpecSheet(spec, fileIndex, selected) {
      const stream = this.zip.openStream(`xl/worksheets/sheet${fileIndex}.xml`);
      let xml = this.sheetHead({ widths: spec.widths, freeze: spec.freeze, selected, gridlines: spec.gridlines !== false, print: !!spec.print });
      for (let r = 0; r < spec.rows.length; r++) {
        const cells = spec.rows[r];
        let ht = spec.heights && spec.heights[r];
        if (!ht && spec.autoHeight && cells) {
          // Rows have a fixed default height, so give wrapped text room.
          let lines = 1;
          cells.forEach((cell, c) => {
            if (cell && typeof cell === 'object' && cell.s === ST.td && typeof cell.v === 'string') {
              lines = Math.max(lines, wrappedLines(cell.v, (spec.widths[c] || 10) * 1.25 - 2));
            }
          });
          if (lines > 1) ht = Math.min(lines, 10) * 15 + 6;
        }
        if ((!cells || !cells.length) && !ht) continue;
        xml += `<row r="${r + 1}"${ht ? ` ht="${ht}" customHeight="1"` : ''}>`;
        if (!cells) { xml += '</row>'; continue; }
        for (let c = 0; c < cells.length; c++) {
          let cell = cells[c];
          let s = 0;
          if (cell !== null && typeof cell === 'object') { s = cell.s || 0; cell = cell.v; }
          const ref = colLetter(c) + (r + 1);
          if (cell === null || cell === undefined || cell === '') {
            if (s) xml += `<c r="${ref}" s="${s}"/>`; // keeps borders/fills across merged cells
            continue;
          }
          if (typeof cell === 'number') {
            xml += `<c r="${ref}"${s ? ` s="${s}"` : ''}><v>${Number.isFinite(cell) ? cell : 0}</v></c>`;
          } else {
            let v = String(cell);
            if (v.length > XLSX_MAX_CELL) v = v.slice(0, XLSX_MAX_CELL - 12) + ' [truncated]';
            xml += `<c r="${ref}"${s ? ` s="${s}"` : ''} t="inlineStr"><is><t xml:space="preserve">${xmlEscape(v)}</t></is></c>`;
          }
        }
        xml += '</row>';
        if (xml.length >= FLUSH_SIZE) { await stream.write(xml); xml = ''; await this.sink.flush(); }
      }
      xml += '</sheetData>';
      if (spec.filter) xml += `<autoFilter ref="${spec.filter}"/>`;
      if (spec.merges && spec.merges.length) {
        xml += `<mergeCells count="${spec.merges.length}">${spec.merges.map(m => `<mergeCell ref="${m}"/>`).join('')}</mergeCells>`;
      }
      if (spec.print) {
        // Print centred on A4 portrait, one page wide.
        xml += '<printOptions horizontalCentered="1"/>' +
          '<pageMargins left="0.4" right="0.4" top="0.5" bottom="0.5" header="0.3" footer="0.3"/>' +
          '<pageSetup paperSize="9" orientation="portrait" fitToWidth="1" fitToHeight="0"/>';
      }
      if (spec.charts && spec.charts.length) xml += '<drawing r:id="rId1"/>';
      await stream.write(xml + '</worksheet>');
      await stream.close();
      await this.sink.flush();
    }

    // summary: { sheets: [spec, \u2026] }, placed before the findings sheets.
    async finish(summary) {
      await this.flush();
      await this.endSheet();
      const findings = this.sheetRows.length;
      const lastCol = this.letters[this.letters.length - 1];
      const specs = summary ? summary.sheets : [];

      // Workbook order is summaries first, then findings. Findings were
      // already streamed as sheet1..N, so summaries take the next numbers.
      const book = [];
      const drawings = [];
      let chartNo = 0;
      for (let k = 0; k < specs.length; k++) {
        const spec = specs[k];
        const file = findings + k + 1;
        await this.writeSpecSheet(spec, file, k === 0);
        book.push({ name: spec.name, file, filter: spec.filter ? spec.filter.replace(/([A-Z]+)(\d+)/g, '$$$1$$$2') : null });
        if (spec.charts && spec.charts.length) {
          const d = drawings.length + 1;
          const charts = spec.charts.map(() => ++chartNo);
          spec.charts.forEach((an, j) => this.zip.addFile(`xl/charts/chart${charts[j]}.xml`, chartXml({ ...an.chart, sheet: spec.name })));
          this.zip.addFile(`xl/drawings/drawing${d}.xml`, drawingXml(spec.charts));
          this.zip.addFile(`xl/drawings/_rels/drawing${d}.xml.rels`, XML_DECL +
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
            charts.map((n, j) => `<Relationship Id="rId${j + 1}" Type="${NS_REL}/chart" Target="../charts/chart${n}.xml"/>`).join('') +
            '</Relationships>');
          this.zip.addFile(`xl/worksheets/_rels/sheet${file}.xml.rels`, XML_DECL +
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
            `<Relationship Id="rId1" Type="${NS_REL}/drawing" Target="../drawings/drawing${d}.xml"/></Relationships>`);
          drawings.push({ d, charts });
        }
      }
      for (let i = 0; i < findings; i++) {
        book.push({ name: this.sheetName(i), file: i + 1, filter: `$A$1:$${lastCol}$${this.sheetRows[i] + 1}` });
      }

      this.zip.addFile('[Content_Types].xml', XML_DECL +
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' +
        '<Default Extension="xml" ContentType="application/xml"/>' +
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>' +
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>' +
        book.map(b => `<Override PartName="/xl/worksheets/sheet${b.file}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`).join('') +
        drawings.map(({ d, charts }) =>
          `<Override PartName="/xl/drawings/drawing${d}.xml" ContentType="application/vnd.openxmlformats-officedocument.drawing+xml"/>` +
          charts.map(n => `<Override PartName="/xl/charts/chart${n}.xml" ContentType="application/vnd.openxmlformats-officedocument.drawingml.chart+xml"/>`).join('')).join('') +
        '</Types>');
      this.zip.addFile('_rels/.rels', XML_DECL +
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
        `<Relationship Id="rId1" Type="${NS_REL}/officeDocument" Target="xl/workbook.xml"/></Relationships>`);
      this.zip.addFile('xl/workbook.xml', XML_DECL +
        `<workbook xmlns="${NS_MAIN}" xmlns:r="${NS_REL}"><bookViews><workbookView activeTab="0"/></bookViews><sheets>` +
        book.map((b, i) => `<sheet name="${escAttr(b.name)}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`).join('') +
        '</sheets><definedNames>' +
        book.map((b, i) => (b.filter
          ? `<definedName name="_xlnm._FilterDatabase" localSheetId="${i}" hidden="1">${escAttr(`'${b.name}'`)}!${b.filter}</definedName>`
          : '')).join('') +
        '</definedNames></workbook>');
      this.zip.addFile('xl/_rels/workbook.xml.rels', XML_DECL +
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
        book.map((b, i) => `<Relationship Id="rId${i + 1}" Type="${NS_REL}/worksheet" Target="worksheets/sheet${b.file}.xml"/>`).join('') +
        `<Relationship Id="rId${book.length + 1}" Type="${NS_REL}/styles" Target="styles.xml"/></Relationships>`);
      this.zip.addFile('xl/styles.xml', stylesXml());
      this.zip.finish();
      return { sheets: findings, summarySheets: specs.map(s => s.name), truncatedCells: this.truncated };
    }
  }

  // ---------------------------------------------------------------------
  // Summary / dashboard. Aggregates are collected for every output row and
  // turned into sheet specs when the workbook is finished.
  // ---------------------------------------------------------------------
  const MAX_CVES_PER_PLUGIN = 50;

  class SummaryCollector {
    constructor() {
      this.sev = [0, 0, 0, 0, 0, 0];
      this.comp = [0, 0, 0, 0];
      this.hosts = new Map();       // target key -> { host, ip, fqdn, os, report, sev[6], comp[4] }
      this.plugins = new Map();     // plugin id -> { name, family, sev, rows, hosts, cves }
      this.checks = new Map();      // check name -> { audit, comp[4] }
      this.pairs = new HashSet64(); // (plugin, target) pairs, for "targets affected"
      this.sevHosts = [new Set(), new Set(), new Set(), new Set(), new Set(), new Set()];
      this.auth = [];               // one entry per distinct failed-login finding
      this.authSeen = new HashSet64();
      this.authHosts = new Set();
    }

    // a.key is the target key (see targetKey in merge), so failures of two
    // databases on one host are kept apart when targets include the report.
    addAuth(a) {
      const [x, y] = hash64([a.key, a.plugin, a.protocol, a.port, a.output].join('\x1f'));
      if (!this.authSeen.add(x, y)) return; // same finding seen again for this target
      if (a.key) { this.authHosts.add(a.key); this.host(a.key, a); }
      if (this.auth.length < XLSX_MAX_ROWS) this.auth.push({ ...a, parsed: parseAuthOutput(a.output) });
    }

    host(key, info) {
      let h = this.hosts.get(key);
      if (!h) {
        h = { host: info.host || '', ip: '', fqdn: '', os: '', report: info.report || '', sev: [0, 0, 0, 0, 0, 0], comp: [0, 0, 0, 0] };
        this.hosts.set(key, h);
      }
      if (!h.ip && info.ip) h.ip = info.ip;
      if (!h.fqdn && info.fqdn) h.fqdn = info.fqdn;
      if (!h.os && info.os) h.os = info.os;
      return h;
    }

    addVuln(hostName, h, bucket, pluginId, name, family, cve) {
      this.sev[bucket]++;
      if (h) { h.sev[bucket]++; this.sevHosts[bucket].add(hostName); }
      if (!pluginId) return;
      let p = this.plugins.get(pluginId);
      if (!p) {
        p = { name, family, sev: bucket, rows: 0, hosts: 0, cves: new Set() };
        this.plugins.set(pluginId, p);
      }
      p.rows++;
      if (bucket < p.sev) p.sev = bucket;
      if (!p.name && name) p.name = name;
      if (!p.family && family) p.family = family;
      if (cve && p.cves.size < MAX_CVES_PER_PLUGIN) p.cves.add(cve);
      if (hostName) {
        const [a, b] = hash64(pluginId + '\x1f' + hostName);
        if (this.pairs.add(a, b)) p.hosts++;
      }
    }

    addCompliance(h, bucket, check, audit) {
      this.comp[bucket]++;
      if (h) h.comp[bucket]++;
      const key = check || '(unnamed check)';
      let c = this.checks.get(key);
      if (!c) { c = { audit: audit || '', comp: [0, 0, 0, 0] }; this.checks.set(key, c); }
      c.comp[bucket]++;
    }

    get vulnTotal() { return this.sev.reduce((a, b) => a + b, 0); }
    get authTotal() { return this.authHosts.size; }
    get compTotal() { return this.comp.reduce((a, b) => a + b, 0); }
  }

  // Plain summary-sheet values -> bordered, padded table cells.
  const tableCells = cells => cells.map(c => {
    if (c === null || c === undefined || c === '') return { v: '', s: ST.tdNum };
    if (typeof c === 'number') return { v: c, s: ST.tdNum };
    if (typeof c === 'string') return { v: c, s: ST.td };
    if (c.s === ST.pct) return { v: c.v, s: ST.tdPct };
    return c;
  });

  const ratio = (n, d) => (d ? n / d : 0);
  const asNumber = v => (NUMERIC.test(v) ? Number(v) : v);
  const passRate = comp => ratio(comp[0], comp[0] + comp[1] + comp[2]);
  const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });

  const IDENTITY_NOTES = {
    hostip: 'Targets are host name + IP address (e.g. Oracle RAC nodes that share a host name are counted separately).',
    report: 'Targets are host + report: each report is treated as a separate database, even when several share a host.',
  };

  function buildSummary(agg, meta) {
    const sheets = [];
    const byHost = meta.identity === 'host';
    const T = byHost ? { one: 'host', Many: 'Hosts', many: 'hosts' } : { one: 'target', Many: 'Targets', many: 'targets' };
    const showReport = meta.identity === 'report';
    const label = h => h.host + (h.ip && h.ip !== h.host && !byHost ? ` (${h.ip})` : '') + (showReport && h.report ? ` \u2014 ${h.report}` : '');
    const hasVulns = agg.vulnTotal > 0;
    const hasComp = agg.compTotal > 0;
    const sevRows = SEVERITIES.filter((s, i) => i < 5 || agg.sev[5] > 0);
    const compScore = passRate(agg.comp);

    const hostList = [...agg.hosts].sort((x, y) => {
      const a = x[1], b = y[1];
      for (let i = 0; i < 4; i++) if (a.sev[i] !== b.sev[i]) return b.sev[i] - a.sev[i];
      if (a.comp[1] !== b.comp[1]) return b.comp[1] - a.comp[1];
      return collator.compare(a.host, b.host) || collator.compare(a.ip, b.ip) || collator.compare(a.report, b.report);
    });
    const pluginList = [...agg.plugins].sort((x, y) =>
      x[1].sev - y[1].sev || y[1].hosts - x[1].hosts || y[1].rows - x[1].rows || collator.compare(x[0], y[0]));
    const checkList = [...agg.checks].sort((x, y) =>
      y[1].comp[1] - x[1].comp[1] || y[1].comp[2] - x[1].comp[2] || collator.compare(x[0], y[0]));

    const authList = agg.auth.slice().sort((x, y) =>
      collator.compare(x.host, y.host) || collator.compare(x.ip, y.ip) || collator.compare(x.source, y.source) || collator.compare(x.port, y.port));

    // --- Dashboard: an 8-column grid (B\u2013I) between narrow margins, gridlines
    // off. Every row's spans add up to 8 so tables line up and stay centred;
    // charts get their own reserved rows so they never cover a table.
    const GRID = 8;
    const COL_WIDTH = 16;
    const rows = [];
    const merges = [];
    const heights = {};
    const blank = ht => { rows.push([]); if (ht) heights[rows.length - 1] = ht; };
    const WRAPPED = new Set([ST.td, ST.tdBold, ST.header, ST.note]);
    // items: [{ v, s, span }]; returns the 1-based row number.
    const line = (items, ht) => {
      const r = rows.length + 1;
      const cells = [null]; // column A is the left margin
      let lines = 1;
      for (const it of items) {
        const span = it.span || 1;
        const start = cells.length;
        cells.push({ v: it.v, s: it.s || 0 });
        for (let k = 1; k < span; k++) cells.push({ v: '', s: it.s || 0 });
        if (span > 1 && (it.s || (it.v !== '' && it.v !== null && it.v !== undefined))) {
          merges.push(`${colLetter(start)}${r}:${colLetter(start + span - 1)}${r}`);
        }
        // Merged cells don't auto-fit, so size wrapped text explicitly.
        if (typeof it.v === 'string' && WRAPPED.has(it.s)) {
          // Column width is measured in digit widths; text averages ~0.8 of that.
          lines = Math.max(lines, wrappedLines(it.v, span * COL_WIDTH * 1.25 - 2));
        }
      }
      rows.push(cells);
      const auto = lines > 1 ? Math.min(lines, 8) * 15 + 6 : 0;
      heights[r - 1] = Math.max(ht || 20, auto);
      return r;
    };
    const full = (v, s, ht) => line([{ v, s, span: GRID }], ht);
    const head = labels => line(labels.map(([v, span]) => ({ v, s: ST.header, span })), 24);

    full('Tenable Report \u2014 Merged Summary', ST.title, 34);
    full(`Generated ${meta.generated} from ${meta.reports} report${meta.reports === 1 ? '' : 's'}` +
      (meta.appVersion ? ` \u00B7 Tenable Report Merger v${meta.appVersion}` : ''), ST.subtitle, 18);
    blank(10);

    // KPI tiles: 4 per row (2 columns each); a short last row is centred.
    const kpis = [['Reports merged', meta.reports, ST.kpiValue], [T.Many, agg.hosts.size, ST.kpiValue]];
    if (hasComp) {
      kpis.push(['Compliance score', compScore, ST.kpiPct],
        ['Failed checks', agg.comp[1], agg.comp[1] ? ST.kpiBad : ST.kpiGood],
        ['Warning / Manual check', agg.comp[2], ST.kpiValue]);
    }
    if (hasVulns) {
      const ch = agg.sev[0] + agg.sev[1];
      kpis.push(['Vulnerability findings', agg.vulnTotal, ST.kpiValue], ['Critical + High findings', ch, ch ? ST.kpiBad : ST.kpiGood]);
    }
    if (meta.authPlugins.length) {
      kpis.push([`${T.Many} with failed authentication`, agg.authTotal, agg.authTotal ? ST.kpiBad : ST.kpiGood]);
    }
    kpis.push(['Duplicates removed', meta.duplicates, ST.kpiValue], ['Rows excluded (info / rules)', meta.excluded, ST.kpiValue]);
    for (let i = 0; i < kpis.length; i += 4) {
      const group = kpis.slice(i, i + 4);
      const free = GRID - group.length * 2;
      const pad = (n, items) => (n ? [{ v: '', span: n }, ...items] : items);
      const withPads = items => {
        const left = Math.floor(free / 2);
        const out = pad(left, items);
        return free - left ? [...out, { v: '', span: free - left }] : out;
      };
      line(withPads(group.map(([, v, s]) => ({ v, s, span: 2 }))), 36);
      line(withPads(group.map(([label]) => ({ v: label, s: ST.kpiLabel, span: 2 }))), 30);
      blank(8);
    }

    // Charts: side by side across the grid, or one centred chart.
    const chartTypes = [hasVulns && 'bar', hasComp && 'doughnut'].filter(Boolean);
    const CHART_ROWS = 20;
    let chartTop = -1;
    if (chartTypes.length) {
      blank(6);
      chartTop = rows.length; // zero-based row index where charts start
      for (let i = 0; i < CHART_ROWS; i++) blank();
      blank(10);
    }
    const anchors = chartTypes.length === 2
      ? { bar: [1, 5], doughnut: [5, 9] }
      : { [chartTypes[0]]: [2, 8] }; // columns C\u2013H, centred
    const charts = [];
    const addChart = (type, chart) => {
      const [c0, c1] = anchors[type];
      charts.push({ from: [c0, chartTop], to: [c1, chartTop + CHART_ROWS], chart: { type, ...chart } });
    };

    if (IDENTITY_NOTES[meta.identity]) full(IDENTITY_NOTES[meta.identity], ST.note);
    if (meta.findingsSheets > 1) {
      full(`Findings continue across ${meta.findingsSheets} sheets (Findings to ${findingsSheetName(meta.findingsSheets - 1)}). Excel allows at most 1,048,576 rows per sheet; the Sources sheet shows which sheet holds each report.`, ST.note);
    }
    blank(10);

    if (hasVulns) {
      full('Vulnerabilities by severity', ST.section, 24);
      head([['Severity', 2], ['Findings', 2], ['% of findings', 2], [`${T.Many} affected`, 2]]);
      const first = rows.length + 1;
      for (const sev of sevRows) {
        const i = SEVERITIES.indexOf(sev);
        line([{ v: sev[0], s: sev[1], span: 2 }, { v: agg.sev[i], s: ST.tdNum, span: 2 },
          { v: ratio(agg.sev[i], agg.vulnTotal), s: ST.tdPct, span: 2 }, { v: agg.sevHosts[i].size, s: ST.tdNum, span: 2 }]);
      }
      const last = rows.length;
      line([{ v: 'Total', s: ST.tdBold, span: 2 }, { v: agg.vulnTotal, s: ST.tdNumBold, span: 2 },
        { v: 1, s: ST.tdPct, span: 2 }, { v: '', s: ST.tdNum, span: 2 }]);
      blank(10);
      addChart('bar', {
        title: 'Vulnerability findings by severity', catRange: `$B$${first}:$B$${last}`, valRange: `$D$${first}:$D$${last}`,
        cats: sevRows.map(s => s[0]), vals: sevRows.map(s => agg.sev[SEVERITIES.indexOf(s)]), colors: sevRows.map(s => s[2]),
      });
    }

    if (hasComp) {
      full('Compliance results', ST.section, 24);
      head([['Result', 4], ['Checks', 2], ['% of checks', 2]]);
      const first = rows.length + 1;
      COMPLIANCE_RESULTS.forEach(([label, style], i) => line([{ v: label, s: style, span: 4 },
        { v: agg.comp[i], s: ST.tdNum, span: 2 }, { v: ratio(agg.comp[i], agg.compTotal), s: ST.tdPct, span: 2 }]));
      const last = rows.length;
      line([{ v: 'Total', s: ST.tdBold, span: 4 }, { v: agg.compTotal, s: ST.tdNumBold, span: 2 }, { v: 1, s: ST.tdPct, span: 2 }]);
      line([{ v: 'Compliance score', s: ST.tdBold, span: 4 }, { v: compScore, s: ST.tdPct, span: 4 }]);
      full('Score = Passed \u00F7 (Passed + Failed + Warning / Manual check)', ST.note);
      blank(10);
      addChart('doughnut', {
        title: 'Compliance results', catRange: `$B$${first}:$B$${last}`, valRange: `$F$${first}:$F$${last}`,
        cats: COMPLIANCE_RESULTS.map(r => r[0]), vals: agg.comp.slice(), colors: COMPLIANCE_RESULTS.map(r => r[2]),
      });
    }

    if (meta.authPlugins.length) {
      full(`Authentication failures (plugin ${meta.authPlugins.join(', ')})`, ST.section, 24);
      if (!authList.length) {
        line([{ v: 'No authentication failures found. Credentials worked on every target that reported.', s: ST.passed, span: GRID }], 20);
      } else {
        full(`${agg.authTotal} ${agg.authTotal === 1 ? T.one : T.many} could not be scanned with the provided credentials, so their results may be incomplete.`, ST.note);
        const cols = showReport
          ? [['Host', 1], ['IP Address', 1], ['Report', 2], ['Protocol / Port', 1], ['User', 1], ['Error', 2]]
          : [['Host', 2], ['IP Address', 1], ['Protocol / Port', 1], ['User', 1], ['Error', 3]];
        head(cols);
        const AUTH_ON_DASHBOARD = 25;
        for (const a of authList.slice(0, AUTH_ON_DASHBOARD)) {
          const errText = a.parsed.error || (a.output ? a.output.replace(/\s+/g, ' ').slice(0, 200) : '');
          const vals = {
            'Host': { v: a.host, s: ST.tdBold }, 'IP Address': { v: a.ip, s: ST.tdNum }, 'Report': { v: a.source, s: ST.td },
            'Protocol / Port': { v: [a.parsed.protocol || a.protocol, a.parsed.port || a.port].filter(Boolean).join(' / '), s: ST.tdNum },
            'User': { v: a.parsed.user, s: ST.tdNum }, 'Error': { v: errText, s: ST.td },
          };
          line(cols.map(([name, span]) => ({ ...vals[name], span })));
        }
        if (authList.length > AUTH_ON_DASHBOARD) {
          full(`\u2026 and ${authList.length - AUTH_ON_DASHBOARD} more. See the "Auth Failures" sheet.`, ST.note);
        }
      }
      blank(10);
    }

    if (hostList.length) {
      full(`Top 10 ${T.many} by risk`, ST.section, 24);
      const name = byHost ? 'Host' : 'Target';
      if (hasVulns && hasComp) {
        head([[name, 2], ['Critical', 1], ['High', 1], ['Medium', 1], ['Low', 1], ['Failed checks', 1], ['Pass rate', 1]]);
      } else if (hasVulns) {
        head([[name, 4], ['Critical', 1], ['High', 1], ['Medium', 1], ['Low', 1]]);
      } else {
        head([[name, 4], ['Failed', 1], ['Warning / Manual', 1], ['Passed', 1], ['Pass rate', 1]]);
      }
      for (const [, h] of hostList.slice(0, 10)) {
        const rate = h.comp.some(Boolean) ? { v: passRate(h.comp), s: ST.tdPct } : { v: '', s: ST.tdNum };
        const num = v => ({ v, s: ST.tdNum });
        if (hasVulns && hasComp) {
          line([{ v: label(h), s: ST.td, span: 2 }, ...h.sev.slice(0, 4).map(num), num(h.comp[1]), rate]);
        } else if (hasVulns) {
          line([{ v: label(h), s: ST.td, span: 4 }, ...h.sev.slice(0, 4).map(num)]);
        } else {
          line([{ v: label(h), s: ST.td, span: 4 }, num(h.comp[1]), num(h.comp[2]), num(h.comp[0]), rate]);
        }
      }
      blank(10);
    }
    if (hasVulns && pluginList.length) {
      full('Top 10 vulnerabilities', ST.section, 24);
      head([['Name', 5], ['Plugin ID', 1], ['Severity', 1], [T.Many, 1]]);
      for (const [id, p] of pluginList.slice(0, 10)) {
        line([{ v: p.name || id, s: ST.td, span: 5 }, { v: asNumber(id), s: ST.tdNum },
          { v: SEVERITIES[p.sev][0], s: SEVERITIES[p.sev][1] }, { v: p.hosts, s: ST.tdNum }]);
      }
      blank(10);
    }
    if (hasComp && checkList.length) {
      full('Top 10 failed compliance checks', ST.section, 24);
      head([['Check', 4], ['Failed', 1], ['Warning / Manual', 1], ['Passed', 1], ['Pass rate', 1]]);
      for (const [check, c] of checkList.slice(0, 10)) {
        line([{ v: check, s: ST.td, span: 4 }, { v: c.comp[1], s: ST.tdNum }, { v: c.comp[2], s: ST.tdNum },
          { v: c.comp[0], s: ST.tdNum }, { v: passRate(c.comp), s: ST.tdPct }]);
      }
    }
    sheets.push({
      name: 'Dashboard', widths: [2, ...Array(GRID).fill(COL_WIDTH), 2], rows, merges, heights,
      freeze: false, gridlines: false, print: true, charts,
    });

    // --- Hosts
    if (hostList.length) {
      const anyIp = hostList.some(([, h]) => h.ip);
      const anyFqdn = hostList.some(([, h]) => h.fqdn);
      const anyOs = hostList.some(([, h]) => h.os);
      const head = ['Host'];
      const widths = [22];
      if (anyIp) { head.push('IP Address'); widths.push(16); }
      if (showReport) { head.push('Report'); widths.push(40); }
      if (anyFqdn) { head.push('FQDN'); widths.push(30); }
      if (anyOs) { head.push('OS'); widths.push(34); }
      if (hasVulns) { head.push('Critical', 'High', 'Medium', 'Low', 'Info', 'Total'); widths.push(10, 10, 10, 10, 10, 10); }
      if (hasComp) { head.push('Passed', 'Failed', 'Warning / Manual', 'Error / other', 'Pass rate'); widths.push(10, 10, 17, 13, 11); }
      const showAuth = agg.authTotal > 0;
      if (showAuth) { head.push('Auth Failed'); widths.push(12); }
      const hostRows = [head.map(v => ({ v, s: ST.header }))];
      for (const [key, h] of hostList.slice(0, XLSX_MAX_ROWS)) {
        const cells = [h.host];
        if (anyIp) cells.push(h.ip);
        if (showReport) cells.push(h.report);
        if (anyFqdn) cells.push(h.fqdn);
        if (anyOs) cells.push(h.os);
        if (hasVulns) cells.push(...h.sev.slice(0, 5), h.sev.reduce((a, b) => a + b, 0));
        if (hasComp) cells.push(...h.comp, h.comp.some(Boolean) ? { v: passRate(h.comp), s: ST.pct } : null);
        if (showAuth) cells.push(agg.authHosts.has(key) ? { v: 'Yes', s: ST.failed } : null);
        hostRows.push(tableCells(cells));
      }
      sheets.push({ name: T.Many, widths, rows: hostRows, freeze: true, autoHeight: true, heights: { 0: 24 }, filter: `A1:${colLetter(head.length - 1)}${hostRows.length}` });
    }

    // --- Vulnerabilities
    if (hasVulns && pluginList.length) {
      const anyFamily = pluginList.some(([, p]) => p.family);
      const head = ['Plugin ID', 'Name', ...(anyFamily ? ['Plugin Family'] : []), 'Severity', `${T.Many} Affected`, 'Occurrences', 'CVEs'];
      const vulnRows = [head.map(v => ({ v, s: ST.header }))];
      for (const [id, p] of pluginList.slice(0, XLSX_MAX_ROWS)) {
        vulnRows.push(tableCells([asNumber(id), p.name, ...(anyFamily ? [p.family] : []),
          { v: SEVERITIES[p.sev][0], s: SEVERITIES[p.sev][1] }, p.hosts, p.rows,
          [...p.cves].join(', ') + (p.cves.size >= MAX_CVES_PER_PLUGIN ? ', \u2026' : '')]));
      }
      sheets.push({
        name: 'Vulnerabilities', widths: [10, 60, ...(anyFamily ? [24] : []), 10, 15, 13, 40], rows: vulnRows, autoHeight: true, heights: { 0: 24 },
        freeze: true, filter: `A1:${colLetter(head.length - 1)}${vulnRows.length}`,
      });
    }

    // --- Compliance
    if (hasComp) {
      const anyAudit = checkList.some(([, c]) => c.audit);
      const head = ['Check', ...(anyAudit ? ['Audit File'] : []), 'Passed', 'Failed', 'Warning / Manual', 'Error / other', 'Total', 'Pass rate'];
      const compRows = [head.map(v => ({ v, s: ST.header }))];
      for (const [check, c] of checkList.slice(0, XLSX_MAX_ROWS)) {
        compRows.push(tableCells([check, ...(anyAudit ? [c.audit] : []), ...c.comp, c.comp.reduce((a, b) => a + b, 0), { v: passRate(c.comp), s: ST.pct }]));
      }
      sheets.push({
        name: 'Compliance', widths: [80, ...(anyAudit ? [30] : []), 10, 10, 17, 13, 10, 11], rows: compRows, autoHeight: true, heights: { 0: 24 },
        freeze: true, filter: `A1:${colLetter(head.length - 1)}${compRows.length}`,
      });
    }

    // --- Auth Failures
    if (authList.length) {
      const head = ['Host', 'IP Address', 'FQDN', 'OS', 'Auth Protocol', 'Port', 'User', 'Domain', 'Error', 'Plugin ID', 'Plugin Name', 'Plugin Output', 'Source Report'];
      const authRows = [head.map(v => ({ v, s: ST.header }))];
      for (const a of authList) {
        authRows.push(tableCells([a.host, a.ip, a.fqdn, a.os, a.parsed.protocol || a.protocol, asNumber(a.parsed.port || a.port),
          a.parsed.user, a.parsed.domain, a.parsed.error, asNumber(a.plugin), a.name, a.output, a.source]));
      }
      sheets.push({
        name: 'Auth Failures', widths: [20, 15, 28, 28, 14, 8, 18, 14, 50, 10, 45, 60, 40], rows: authRows, autoHeight: true, heights: { 0: 24 },
        freeze: true, filter: `A1:M${authRows.length}`,
      });
    }

    // --- Sources
    const srcHead = ['Report', 'Type', 'Rows read', 'Rows written', 'Findings sheet', 'Duplicates removed', 'Info excluded', 'Removed by rules', 'Auth failures', 'Status'];
    const srcRows = [srcHead.map(v => ({ v, s: ST.header }))];
    meta.sources.forEach((src, i) => {
      const st = meta.perFile[i] || {};
      const where = st.sheetFirst === null || st.sheetFirst === undefined ? '\u2014'
        : findingsSheetName(st.sheetFirst) + (st.sheetLast > st.sheetFirst ? ` to ${findingsSheetName(st.sheetLast)}` : '');
      srcRows.push(tableCells([src.name, src.kind === 'nessus' ? '.nessus' : 'CSV', st.rowsIn || 0, st.rowsOut || 0, where,
        st.duplicates || 0, st.filtered || 0, st.excluded || 0, st.auth || 0,
        st.error ? `Error: ${st.error}` : st.rowsIn && !st.rowsOut ? 'OK (no rows left after filters)' : 'OK']));
    });
    sheets.push({ name: 'Sources', widths: [60, 9, 12, 13, 26, 18, 13, 16, 13, 30], rows: srcRows, freeze: true, autoHeight: true, heights: { 0: 24 }, filter: `A1:J${srcRows.length}` });

    return { sheets };
  }

  // ---------------------------------------------------------------------
  // Merge
  // ---------------------------------------------------------------------
  let cancelled = false;

  // Guards against damaged copies of this file: if a download or copy-paste
  // altered the character classes above (e.g. turned the escaped
  // non-characters into spaces), every space would be stripped from the
  // workbook. Refuse to run instead.
  function selfCheck() {
    if (xmlEscape('a b & c') !== 'a b &amp; c' || BAD_XML_CHARS.test(' ') || csvEscape('a b') !== '"a b"') {
      throw new Error('merge-worker.js is damaged (its text handling no longer keeps spaces). ' +
        'Download the ZIP again from GitHub (Code > Download ZIP), extract all files, and reopen index.html.');
    }
  }

  async function merge(msg) {
    cancelled = false;
    selfCheck();
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
    const withSummary = options.format === 'xlsx' && options.summary !== false;
    const complianceMode = options.mode === 'compliance';
    // What makes two rows belong to the same target: the host name, host + IP
    // (Oracle RAC nodes sharing a name), or host + report (one database per
    // report). Used for duplicate removal and every per-target summary.
    const identity = ['hostip', 'report'].includes(options.identity) ? options.identity : 'host';
    const authIds = new Set((options.authPlugins || []).map(v => String(v).trim()).filter(Boolean));
    const out = options.format === 'xlsx'
      ? new XlsxOutput(sink, outCols, withSummary, options.findingsRows === 'fit')
      : new CsvOutput(sink, outCols, options.bom);

    const totalBytes = sources.reduce((s, src) => s + sourceBytes(src), 0);
    let bytesDone = 0;
    let lastProgress = 0;
    const seen = options.dedupe === 'none' ? null : new HashSet64();
    const agg = new SummaryCollector();
    const severity = Object.create(null); // vulnerability rows by Risk label, for the page
    const totals = { rowsIn: 0, rowsOut: 0, duplicates: 0, filtered: 0, excluded: 0, auth: 0, malformed: 0 };
    const rules = compileRules(options.rules);
    const ruleHits = rules.map(() => 0);
    const perFile = [];
    const outColIndex = new Map(outCols.map((c, i) => [c.toLowerCase(), i]));

    try {
      for (let fi = 0; fi < sources.length; fi++) {
        if (cancelled) break;
        const src = sources[fi];
        const stats = { rowsIn: 0, rowsOut: 0, duplicates: 0, filtered: 0, excluded: 0, auth: 0, malformed: 0, error: null, sheetFirst: null, sheetLast: null };
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

        const cell = (row, k) => (fKey[k] === -1 ? '' : (row[fKey[k]] || '').trim());
        const targetKey = row => {
          const host = cell(row, 'host');
          if (identity === 'hostip') return host + '\x1f' + cell(row, 'ip');
          if (identity === 'report') return host + '\x1f' + fi;
          return host;
        };
        const targetInfo = row => ({
          host: cell(row, 'host'), ip: cell(row, 'ip'), fqdn: cell(row, 'fqdn'), os: cell(row, 'os'), report: src.name,
        });

        const handleRow = row => {
          stats.rowsIn++;
          if (row.length !== fileCols) stats.malformed++;

          const ruleMatch = () => {
            for (let r = 0; r < fRules.length; r++) {
              const rule = fRules[r];
              if (rule.test(row[rule.col] || '')) {
                stats.excluded++;
                ruleHits[rule.index]++;
                return true;
              }
            }
            return false;
          };

          // Authentication-failure plugins are reported on their own (dashboard
          // + "Auth Failures" sheet) and never count as compliance checks or
          // vulnerabilities. With the summary sheets on they are left out of
          // Findings; otherwise (e.g. CSV) they stay so nothing is lost.
          // Explicit exclusion rules still apply.
          const isAuth = authIds.has(cell(row, 'plugin'));
          if (isAuth) {
            if (ruleMatch()) return;
            agg.addAuth({
              ...targetInfo(row), key: cell(row, 'host') ? targetKey(row) : '',
              plugin: cell(row, 'plugin'), name: cell(row, 'name'), protocol: cell(row, 'protocol'),
              port: cell(row, 'port'), output: cell(row, 'output'), source: src.name,
            });
            if (withSummary) { stats.auth++; return; }
          }

          // Compliance results are never "informational": a PASSED check has
          // Risk None, but dropping it would skew the pass rate.
          const compBucket = isAuth || fKey.result === -1 || options.mode === 'vulnerability' ? -1 : complianceBucket(row[fKey.result] || '');

          if (options.excludeInfo && compBucket === -1 && !isAuth && fKey.risk !== -1) {
            const sev = (row[fKey.risk] || '').trim().toLowerCase();
            if (INFO_LEVELS.has(sev)) { stats.filtered++; return; }
          }

          if (!isAuth && ruleMatch()) return;

          if (seen) {
            let key;
            if (options.dedupe === 'key' && fKey.plugin !== -1 && fKey.host !== -1) {
              // Compliance checks share one plugin ID per audit, so the check
              // name is part of what makes a finding distinct.
              const g = k => cell(row, k).toLowerCase();
              key = g('plugin') + '\x1f' + targetKey(row).toLowerCase() + '\x1f' + g('protocol') + '\x1f' + g('port') + '\x1f' + g('cve') + '\x1f' + g('check');
            } else {
              // Exact duplicate: compare the whole source row (within the
              // report only, when each report is its own target).
              key = (identity === 'report' ? fi + '\x1e' : '') + row.join('\x1f');
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
          if (out.currentSheet !== undefined) {
            if (stats.sheetFirst === null) stats.sheetFirst = out.currentSheet;
            stats.sheetLast = out.currentSheet;
          }

          const hostName = cell(row, 'host') ? targetKey(row) : '';
          const h = hostName ? agg.host(hostName, targetInfo(row)) : null;
          if (isAuth) {
            // Counted in the auth section only.
          } else if (compBucket !== -1) {
            agg.addCompliance(h, compBucket, cell(row, 'check'), cell(row, 'audit'));
          } else {
            const risk = cell(row, 'risk');
            agg.addVuln(hostName, h, severityBucket(risk), cell(row, 'plugin'), cell(row, 'name'), cell(row, 'family'), cell(row, 'cve'));
            if (fKey.risk !== -1) severity[risk || 'Unspecified'] = (severity[risk || 'Unspecified'] || 0) + 1;
          }
        };

        // Fills "Compliance Check" / "Compliance Result" where a source lacks
        // them: from the Description ("<check>": [RESULT]) when present and,
        // in compliance-audit mode, from Risk and Name otherwise.
        const fillCompliance = row => {
          if (fKey.result === -1 || authIds.has(cell(row, 'plugin'))) return;
          const hasResult = row[fKey.result] && row[fKey.result].trim();
          const hasCheck = fKey.check === -1 || (row[fKey.check] && row[fKey.check].trim());
          if (hasResult && hasCheck) return;
          const parsed = parseComplianceDesc(cell(row, 'desc'));
          if (!hasResult) row[fKey.result] = parsed ? parsed[1] : complianceMode ? riskToResult(cell(row, 'risk')) : '';
          if (!hasCheck) row[fKey.check] = parsed ? parsed[0] : complianceMode ? cell(row, 'name') : '';
        };

        let parser;
        if (src.kind === 'nessus') {
          setHeaders(NESSUS_COLUMNS);
          parser = new NessusStreamParser(row => { fillCompliance(row); return handleRow(row); });
        } else {
          let rawCols = 0;
          let derive = false;
          parser = new CsvStreamParser(row => {
            if (map === null) {
              let headers = row.map(normalizeHeader);
              rawCols = headers.length;
              derive = (src.derive || complianceMode) && findColumn(headers, KEY_ALIASES.result) === -1;
              if (derive) headers = headers.concat(DERIVED_COLUMNS);
              setHeaders(headers);
              return;
            }
            if (derive) {
              // Normalise the length first so the derived values land in their columns.
              if (row.length !== rawCols) { stats.malformed++; row.length = rawCols; }
              row.push('', '');
            }
            fillCompliance(row);
            handleRow(row);
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

      const summary = withSummary ? buildSummary(agg, {
        generated: new Date().toLocaleString(),
        reports: sources.length,
        duplicates: totals.duplicates,
        excluded: totals.filtered + totals.excluded,
        authPlugins: [...authIds],
        identity,
        appVersion: options.appVersion || '',
        findingsSheets: out.sheetRows ? out.sheetRows.length : 1,
        sources,
        perFile,
      }) : null;
      const extra = await out.finish(summary);
      const blob = await sink.close(out.mime);
      self.postMessage({
        type: 'done',
        blob,
        stats: {
          ...totals,
          ...extra,
          format: options.format,
          columns: outCols.length,
          uniqueHosts: agg.hosts.size,
          severity,
          compliance: agg.comp.slice(),
          identity,
          authHosts: authIds.size ? agg.authTotal : null,
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
      } else if (msg.type === 'version') {
        self.postMessage({ type: 'version', version: WORKER_VERSION });
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
