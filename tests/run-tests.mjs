// Regression tests for the merge engine. Self-contained: builds its own
// sample data, needs only Node 20+.   Run:  node tests/run-tests.mjs
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { File } from 'node:buffer';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const SOURCE = fs.readFileSync(path.join(root, 'merge-worker.js'), 'utf8');

// Fresh worker instance per call, so source patches (e.g. tiny sheet limits)
// stay local to one test.
function loadWorker(source = SOURCE) {
  const msgs = [];
  const scope = { postMessage: m => msgs.push(m) };
  scope.self = scope;
  new Function('self', 'postMessage', source + '\nmergeWorkerMain();')(scope, scope.postMessage);
  const send = async data => { msgs.length = 0; await scope.onmessage({ data }); return msgs.slice(); };
  return { internals: scope.__mergeInternals, send };
}

let failures = 0;
let passes = 0;
const eq = (got, want, label) => {
  if (JSON.stringify(got) === JSON.stringify(want)) { passes++; return; }
  failures++;
  console.log(`FAIL ${label}\n   got  ${JSON.stringify(got)}\n   want ${JSON.stringify(want)}`);
};
const section = name => console.log(`- ${name}`);

const W = loadWorker();
const { CsvStreamParser, NessusStreamParser, ZipWriter, OutputSink, listZip, textChunks } = W.internals;

const csvFile = (name, text) => new File([text], name);
let NESSUS_HEADERS = null;
const NESSUS_COLUMNS_FOR_TESTS = () => NESSUS_HEADERS;
const csvSource = (name, text, extra = {}) => ({ file: csvFile(name, text), kind: 'csv', name, ...extra });
const nessusSource = (name, text) => ({ file: new File([text], name), kind: 'nessus', name });
const parseCsv = text => { const rows = []; const p = new CsvStreamParser(r => { rows.push(r); }); p.push(text); p.end(); return rows; };

async function merge(sources, columns, options, worker = W) {
  const msgs = await worker.send({ type: 'merge', sources, columns, options: { bom: false, rules: [], authPlugins: [], ...options } });
  const done = msgs.find(m => m.type === 'done');
  if (!done) throw new Error('merge failed: ' + JSON.stringify(msgs.filter(m => m.type !== 'progress')));
  return done;
}

// Reads an .xlsx produced by the writer: { sheetName: xml, ... } plus workbook parts.
async function readXlsx(blob) {
  const file = new File([await blob.arrayBuffer()], 'out.xlsx');
  const parts = {};
  for (const entry of await listZip(file)) {
    let text = '';
    for await (const c of textChunks({ file, entry })) text += c.text;
    parts[entry.name] = text;
  }
  const rels = {};
  for (const m of parts['xl/_rels/workbook.xml.rels'].matchAll(/Id="(rId\d+)"[^>]*Target="([^"]+)"/g)) rels[m[1]] = m[2];
  const sheets = {};
  for (const m of parts['xl/workbook.xml'].matchAll(/<sheet name="([^"]+)" sheetId="\d+" r:id="(rId\d+)"\/>/g)) {
    sheets[m[1].replace(/&amp;/g, '&')] = parts['xl/' + rels[m[2]]];
  }
  return { parts, sheets, names: Object.keys(sheets) };
}
const cellTexts = xml => [...(xml || '').matchAll(/<t xml:space="preserve">([^<]*)<\/t>/g)].map(m => m[1]
  .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&'));

// ---------------------------------------------------------------------------
section('source files');
for (const f of ['merge-worker.js', 'app.js', 'index.html']) {
  const text = fs.readFileSync(path.join(root, f), 'utf8');
  eq(/[^\x00-\x7F]/.test(text), false, `${f} is pure ASCII (no characters that can be mangled in transfer)`);
}
const appVersion = /APP_VERSION = '([^']+)'/.exec(fs.readFileSync(path.join(root, 'app.js'), 'utf8'))[1];
eq(W.internals.WORKER_VERSION, appVersion, 'app.js and merge-worker.js versions match');

// ---------------------------------------------------------------------------
section('CSV parser');
{
  const tricky = 'a,b,c\r\n"x, ""y""","multi\r\nline",z\r\n,,\r\n"",plain"quote,"end"""\n\nlast,row,"no newline"';
  const want = [['a', 'b', 'c'], ['x, "y"', 'multi\r\nline', 'z'], ['', '', ''], ['', 'plain"quote', 'end"'], ['last', 'row', 'no newline']];
  let bad = 0;
  for (let size = 1; size <= tricky.length; size++) {
    const rows = []; const p = new CsvStreamParser(r => { rows.push(r); });
    for (let i = 0; i < tricky.length; i += size) p.push(tricky.slice(i, i + size));
    p.end();
    if (JSON.stringify(rows) !== JSON.stringify(want)) bad++;
  }
  eq(bad, 0, 'identical rows for every chunk size');
}

// ---------------------------------------------------------------------------
section('CSV merge, duplicates, rules');
{
  const h = 'Plugin ID,CVE,Risk,Host,Protocol,Port,Name,Plugin Output\n';
  const a = csvSource('a.csv', '﻿' + h + '10,CVE-1,High,10.0.0.1,tcp,443,"SSL ""x""","l1\nl2"\n10,CVE-2,High,10.0.0.1,tcp,443,"SSL ""x""","l1\nl2"\n20,,None,10.0.0.1,tcp,0,Info,x\n');
  const b = csvSource('b.csv', 'Plugin ID,CVE,Risk,Host,Protocol,Port,Name,Synopsis\r\n10,CVE-1,High,10.0.0.1,tcp,443,"SSL ""x""",syn\r\n30,,Critical,10.0.0.2,tcp,22,SSH,s2\r\n');
  const c = csvSource('c.csv', h + '10,CVE-1,High,10.0.0.1,tcp,443,"SSL ""x""","l1\nl2"\n');
  const cols = ['Plugin ID', 'CVE', 'Risk', 'Host', 'Protocol', 'Port', 'Name', 'Plugin Output', 'Synopsis'];
  let d = await merge([a, b, c], cols, { format: 'csv', dedupe: 'none', addSource: true });
  let rows = parseCsv(await d.blob.text());
  eq(rows.length - 1, 6, 'keep everything: all rows');
  eq(rows[1], ['10', 'CVE-1', 'High', '10.0.0.1', 'tcp', '443', 'SSL "x"', 'l1\nl2', '', 'a.csv'], 'quotes, line breaks, BOM header, source column');
  eq(rows[5], ['30', '', 'Critical', '10.0.0.2', 'tcp', '22', 'SSH', '', 's2', 'b.csv'], 'different column sets line up');
  d = await merge([a, b, c], cols, { format: 'csv', dedupe: 'exact', addSource: true });
  eq([d.stats.duplicates, d.stats.rowsOut], [1, 5], 'identical rows removed across reports');
  d = await merge([a, b, c], cols, { format: 'csv', dedupe: 'key', excludeInfo: true });
  eq([d.stats.filtered, d.stats.duplicates], [1, 2], 'info excluded; repeated findings keep one row per CVE');
  d = await merge([a, b, c], cols, { format: 'csv', dedupe: 'none', rules: [{ column: 'plugin id', op: 'in', values: ['20', '25-35'] }] });
  eq([d.stats.excluded, d.stats.ruleHits], [2, [2]], 'rule: list + numeric range');
  d = await merge([a, b, c], cols, { format: 'csv', dedupe: 'none', rules: [{ column: 'Risk', op: 'notin', values: ['critical'] }] });
  eq(d.stats.rowsOut, 1, 'rule: is not one of (keep only)');
  d = await merge([a, b, c], cols, { format: 'csv', dedupe: 'none', rules: [{ column: 'Name', op: 'contains', values: ['ssh'] }, { column: 'CVE', op: 'regex', values: ['^cve-2$'] }] });
  eq(d.stats.ruleHits, [1, 1], 'rule: contains + regex');
  d = await merge([a], cols, { format: 'csv', dedupe: 'none', bom: true });
  eq([...new Uint8Array(await d.blob.arrayBuffer())].slice(0, 3), [0xEF, 0xBB, 0xBF], 'CSV BOM written');
}

// ---------------------------------------------------------------------------
section('.nessus parsing');
const NESSUS = `<?xml version="1.0" ?>
<NessusClientData_v2><Policy><policyName>P &amp; Q</policyName></Policy>
<Report name="Weekly &amp; DMZ" xmlns:cm="http://www.nessus.org/cm">
<ReportHost name="10.0.0.5"><HostProperties><tag name="host-ip">10.0.0.5</tag><tag name="host-fqdn">web01.local</tag></HostProperties>
<ReportItem port="443" svc_name="www" protocol="tcp" severity="2" pluginID="51192" pluginName="SSL Cert" pluginFamily="General">
<description>The server&apos;s cert &lt;x&gt;.</description><cve>CVE-1</cve><cve>CVE-2</cve>
<plugin_output><![CDATA[Subject : <w> & "s"
line2]]></plugin_output><risk_factor>Medium</risk_factor><xref>CWE:295</xref><xref>IAVA:1</xref></ReportItem>
<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="19506" pluginName="Scan Info" pluginFamily="Settings"><risk_factor>None</risk_factor></ReportItem>
</ReportHost>
<ReportHost name="10.0.0.6"><HostProperties></HostProperties>
<ReportItem port="22" svc_name="ssh" protocol="tcp" severity="4" pluginID="99999" pluginName="Bug &quot;x&quot;" pluginFamily="Misc."/>
</ReportHost></Report></NessusClientData_v2>`;
{
  const ref = []; const p = new NessusStreamParser(r => { ref.push(r); }); p.push(NESSUS); p.end();
  NESSUS_HEADERS = (await W.send({ type: 'scan', files: [{ id: 0, file: new File([NESSUS], 'x.nessus') }] }))[0].headers;
  eq(ref.length, 4, 'one row per CVE plus other findings');
  eq([ref[0][0], ref[0][1], ref[0][3], ref[0][4], ref[1][1]], ['51192', 'CVE-1', 'Medium', '10.0.0.5', 'CVE-2'], 'core columns');
  eq(ref[0][9], "The server's cert <x>.", 'entities decoded');
  eq(ref[0][12], 'Subject : <w> & "s"\nline2', 'CDATA kept verbatim');
  eq(ref[0][19], 'CWE:295, IAVA:1', 'repeated elements joined');
  eq([ref[3][3], ref[3][7]], ['Critical', 'Bug "x"'], 'severity fallback, self-closing item, attribute entities');
  let bad = 0;
  for (const size of [1, 7, 13, 64, 1000]) {
    const rows = []; const q = new NessusStreamParser(r => { rows.push(r); });
    for (let i = 0; i < NESSUS.length; i += size) q.push(NESSUS.slice(i, i + size));
    q.end();
    if (JSON.stringify(rows) !== JSON.stringify(ref)) bad++;
  }
  eq(bad, 0, 'identical rows for every chunk size');
  let err = null;
  try { const t = new NessusStreamParser(() => {}); t.push(NESSUS.slice(0, NESSUS.indexOf('</ReportHost>') + 80)); t.end(); } catch (e) { err = e.message; }
  eq(!!err, true, 'truncated file reported');
}

// ---------------------------------------------------------------------------
section('.zip input');
{
  const sink = new OutputSink(null);
  const zip = new ZipWriter(sink);
  zip.addFile('stored/scan.nessus', NESSUS);
  const s = zip.openStream('deflated/extra.csv');
  await s.write('Plugin ID,Risk,Host,Name\n77777,High,10.9.9.9,"SNMP, public"\n');
  await s.close();
  zip.addFile('__MACOSX/._junk', 'x');
  zip.addFile('notes.txt', 'x');
  zip.addFile('inner.zip', 'PK');
  zip.finish();
  const file = new File([await (await sink.close('application/zip')).arrayBuffer()], 'export.zip');
  const [res] = await W.send({ type: 'scan', files: [{ id: 1, file }] });
  eq(res.children.map(c => [c.name, c.kind, !!c.error]), [['stored/scan.nessus', 'nessus', false], ['deflated/extra.csv', 'csv', false]], 'lists .nessus/.csv (stored and deflated), skips the rest');
  eq(res.nested, 1, 'nested archive counted');
  const d = await merge(res.children.map(c => ({ file, entry: c.entry, kind: c.kind, name: c.name })), res.children[0].headers, { format: 'csv', dedupe: 'none' });
  eq(d.stats.rowsOut, 5, 'rows read from inside the archive');
  const [bad] = await W.send({ type: 'scan', files: [{ id: 2, file: new File(['nope'], 'x.zip') }] });
  eq(!!bad.error, true, 'broken archive reported');
}

// ---------------------------------------------------------------------------
section('.xlsx output');
{
  const src = nessusSource('scan.nessus', NESSUS);
  const [scan] = await W.send({ type: 'scan', files: [{ id: 1, file: src.file }] });
  const d = await merge([src], scan.headers, { format: 'xlsx', dedupe: 'none', addSource: true, summary: true, mode: 'auto' });
  const x = await readXlsx(d.blob);
  eq(x.names, ['Dashboard', 'Hosts', 'Vulnerabilities', 'Sources', 'Findings'], 'sheet order');
  const f = x.sheets.Findings;
  eq(/<c r="A2" s="\d+"><v>51192<\/v><\/c>/.test(f), true, 'numbers stored as numbers');
  eq(cellTexts(f).includes('Subject : <w> & "s"\nline2'), true, 'text escaped, line breaks kept');
  eq(/<autoFilter ref="A1:[A-Z]+5"\/>/.test(f), true, 'filter covers header + 4 rows');
  eq(/<c:chart /.test(x.parts['xl/drawings/drawing1.xml']), true, 'dashboard chart present');
  const dash = cellTexts(x.sheets.Dashboard).join('|');
  eq(['Vulnerabilities by severity', '% of findings', 'Database Compliance'].every(t => dash.includes(t)), true, 'dashboard labels keep their spaces');
  // Sheet rollover + per-cell truncation, with a tiny row limit.
  const tiny = loadWorker(SOURCE.replace('const XLSX_MAX_ROWS = 1048575;', 'const XLSX_MAX_ROWS = 1000;'));
  const big = 'Plugin ID,Host,Plugin Output\n' + Array.from({ length: 3000 }, (_, i) => `${i},h${i},"${i === 5 ? 'x'.repeat(40000) : 'o'}"`).join('\n') + '\n';
  const r = await merge([csvSource('b.csv', big)], ['Plugin ID', 'Host', 'Plugin Output'], { format: 'xlsx', summary: false, dedupe: 'none' }, tiny);
  const rx = await readXlsx(r.blob);
  eq([r.stats.sheets, r.stats.truncatedCells, rx.names], [3, 1, ['Findings', 'Findings (2)', 'Findings (3)']], 'rolls over at the row limit, truncates long cells');
}

// ---------------------------------------------------------------------------
section('compliance, auth failures, no-result targets');
{
  const h = 'Plugin ID,Risk,Host,IP Address,Protocol,Port,Name,Description,Plugin Output\n';
  const auth = '"Nessus was unable to log into the following host :\n\n  Protocol        : Oracle\n  Port            : 1521\n  User            : \'audit_ro\'\n  Error           : ORA-01017: invalid username/password\n"';
  const dbA = csvSource('dbA.csv', h +
    '1000001,None,db01,10.2.0.5,tcp,1521,"1.1 Ensure audit trail",d,\n' +
    '1000001,High,db01,10.2.0.5,tcp,1521,"1.2 Ensure remote auth off",d,\n' +
    '1000001,Medium,db01,10.2.0.5,tcp,1521,"1.3 Review manually",d,\n' +
    '19506,None,db01,10.2.0.5,tcp,0,"Nessus Scan Information",d,info\n');
  const dbB = csvSource('dbB.csv', h +
    '1000001,None,db01,10.2.0.5,tcp,1521,"1.1 Ensure audit trail",d,\n' +
    '1000001,High,db01,10.2.0.5,tcp,1521,"1.2 Ensure remote auth off",d,\n');
  const dbC = csvSource('dbC.csv', h + `104410,None,db02,10.2.0.6,tcp,1521,"Target Credential Status",x,${auth}\n`);
  const dbD = csvSource('dbD.csv', h + `104410,None,db02,10.2.0.6,tcp,1521,"Target Credential Status",x,${auth}\n`);
  const dbE = csvSource('dbE.csv', h + '11219,None,db05,10.2.0.9,tcp,1521,"Nessus SYN scanner",x,open\n10335,None,db05,10.2.0.9,tcp,22,"Nessus TCP scanner",x,open\n');
  const cols = ['Plugin ID', 'Risk', 'Host', 'IP Address', 'Protocol', 'Port', 'Name', 'Description', 'Plugin Output', 'Compliance Check', 'Compliance Result'];
  const base = { format: 'xlsx', mode: 'compliance', addSource: true, authPlugins: ['104410'], rules: [{ column: 'Plugin ID', op: 'in', values: ['19506', '11219', '10335'] }] };

  let d = await merge([dbA], cols, { ...base, format: 'csv', dedupe: 'none' });
  eq(d.stats.compliance, [1, 1, 1, 0], 'Risk None/High/Medium = Passed/Failed/Warning');
  d = await merge([dbA, dbB, dbC, dbD, dbE], cols, { ...base, identity: 'host', dedupe: 'exact' });
  eq([d.stats.duplicates, d.stats.authHosts], [2, 1], 'host identity merges databases on one host (old behaviour)');
  d = await merge([dbA, dbB, dbC, dbD, dbE], cols, { ...base, identity: 'report', dedupe: 'exact' });
  eq([d.stats.duplicates, d.stats.authHosts, d.stats.noResults, d.stats.auth, d.stats.uniqueHosts], [0, 2, 1, 2, 5], 'host + report: every database kept; auth and no-result targets counted');
  const x = await readXlsx(d.blob);
  eq(x.names, ['Dashboard', 'Targets', 'Compliance', 'No Results', 'Auth Failures', 'Sources', 'Findings'], 'compliance workbook sheets');
  const findings = cellTexts(x.sheets.Findings).join('|');
  eq([findings.includes('Target Credential Status'), findings.includes('SYN scanner'), findings.includes('Scan Information')], [false, false, false], 'auth, scanner and excluded rows kept out of Findings');
  const nr = cellTexts(x.sheets['No Results']).join('|');
  eq(nr.includes('11219 Nessus SYN scanner, 10335 Nessus TCP scanner') && nr.includes('1521, 22'), true, 'No Results lists plugins and ports');
  eq(cellTexts(x.sheets['Auth Failures']).includes('ORA-01017: invalid username/password'), true, 'auth error parsed from plugin output');
}

// ---------------------------------------------------------------------------
section('Oracle databases (SID from the scan policy)');
{
  const policy = sid => '<Policy><Preferences><PluginsPreferences>' +
    [['Login :', 'audit_ro'], ['Password :', 'S3cretPassw0rd'], ['Oracle service type :', 'SID'], ...(sid ? [['Database SID :', sid]] : [])]
      .map(([n, v]) => `<item><pluginName>Database settings</pluginName><pluginId>33815</pluginId><fullName>Database settings[entry]:${n}</fullName><preferenceName>${n}</preferenceName><preferenceType>entry</preferenceType><preferenceValues></preferenceValues><selectedValue>${v}</selectedValue></item>`).join('') +
    '</PluginsPreferences></Preferences></Policy>';
  const check = (name, res, sev) => `<ReportItem port="1521" svc_name="oracle" protocol="tcp" severity="${sev}" pluginID="33814" pluginName="Database Compliance Checks" pluginFamily="Policy Compliance"><description>"${name}": [${res}]</description><cm:compliance-check-name>${name}</cm:compliance-check-name><cm:compliance-result>${res}</cm:compliance-result><risk_factor>None</risk_factor></ReportItem>`;
  const ora = (sid, file) => nessusSource(file, `<?xml version="1.0" ?><NessusClientData_v2 xmlns:cm="http://www.nessus.org/cm">${policy(sid)}<Report name="Oracle audit" xmlns:cm="http://www.nessus.org/cm"><ReportHost name="oradb01"><HostProperties><tag name="host-ip">10.5.0.7</tag></HostProperties>${check('1.1 Audit trail', 'PASSED', 0)}${check('1.2 Remote auth', 'FAILED', 3)}</ReportHost></Report></NessusClientData_v2>`);
  const sources = [ora('lereg', 'ora_lereg.nessus'), ora('finprd', 'ora_finprd.nessus'), ora('', 'ora_nosid.nessus')];
  const scans = await W.send({ type: 'scan', files: sources.map((s, id) => ({ id, file: s.file })) });
  eq(scans.map(m => m.databases), [['lereg'], ['finprd'], []], 'SID read from each scan policy');
  const cols = [...scans[0].headers, 'Database'];
  const base = { format: 'xlsx', mode: 'compliance', addSource: true };
  let d = await merge(sources, cols, { ...base, dbMode: 'none', identity: 'host', dedupe: 'key' });
  eq([d.stats.duplicates, d.stats.uniqueHosts], [4, 1], 'without Oracle mode: databases on one host collapse');
  d = await merge(sources, cols, { ...base, dbMode: 'oracle', identity: 'host', dedupe: 'key' });
  eq([d.stats.identity, d.stats.duplicates, d.stats.uniqueHosts, d.stats.compliance], ['database', 0, 3, [3, 3, 0, 0]], 'Oracle mode: each database separate (no-SID report kept apart)');
  const x = await readXlsx(d.blob);
  eq(x.names.includes('Databases'), true, 'Databases sheet');
  const dbs = cellTexts(x.sheets.Databases);
  eq(['lereg', 'finprd', '(unnamed, port 1521)', 'Oracle'].every(v => dbs.includes(v)), true, 'Databases sheet names each SID and type');
  const everything = Object.values(x.parts).join('');
  eq([everything.includes('S3cretPassw0rd'), everything.includes('audit_ro')], [false, false], 'scan-policy login/password never written');
  d = await merge([sources[0], { ...sources[0], name: 'copy.nessus' }], cols, { ...base, format: 'csv', dbMode: 'oracle', dedupe: 'exact' });
  eq(d.stats.duplicates, 2, 'the same database reported twice is still de-duplicated');
}

// ---------------------------------------------------------------------------
section('SQL Server instances (one scan, several instances per host)');
{
  // Real layout: compliance checks are local checks on port 0; only the
  // authentication plugin (104410) carries the database port. Only the
  // "sysadmin users" check names the instance. Descriptions mention a
  // placeholder that must not be taken for an instance.
  //  sql01: SALES and HR, each audit run starts with 1.1; check 2.3 repeats
  //         inside an instance's run (one result per database).
  //  sql02: default instance only.
  //  sql03: one check names two instances, single run -> "A / B".
  //  sql05: auth failure on port 1433 only.
  const item = (port, check, res, output = '', svc = 'general') => `<ReportItem port="${port}" svc_name="${svc}" protocol="tcp" severity="${res === 'PASSED' ? 0 : 3}" pluginID="33814" pluginName="Database Compliance Checks" pluginFamily="Policy Compliance">` +
    `<description>"${check}": [${res}] Applies to MSSQL$InstanceName services.</description><cm:compliance-check-name>${check}</cm:compliance-check-name>` +
    `<cm:compliance-result>${res}</cm:compliance-result>${output ? `<cm:compliance-actual-value>${output}</cm:compliance-actual-value>` : ''}` +
    `<cm:compliance-audit-file>CIS_MSSQL_2016_Database_L1.audit</cm:compliance-audit-file><risk_factor>None</risk_factor></ReportItem>`;
  const sysadmins = acct => ` ["sa","SQL_LOGIN"]\n ["NT SERVICE\\\\${acct}","WINDOWS_LOGIN"]\n ["NT AUTHORITY\\\\SYSTEM","WINDOWS_LOGIN"]`;
  const authItem = port => `<ReportItem port="${port}" svc_name="mssql" protocol="tcp" severity="0" pluginID="104410" pluginName="Target Credential Status by Authentication Protocol - Failure for Provided Credentials" pluginFamily="Settings"><plugin_output>Nessus was unable to log into the following host :\n\n  Protocol        : MSSQL\n  Port            : ${port}\n  User            : 'scan'\n  Error           : Login failed\n</plugin_output><risk_factor>None</risk_factor></ReportItem>`;
  const host = (name, ip, items) => `<ReportHost name="${name}"><HostProperties><tag name="host-ip">${ip}</tag></HostProperties>${items.join('')}</ReportHost>`;
  const run = (name, results) => [
    item(0, '1.1 Ensure xp_cmdshell disabled', results[0]),
    item(0, '2.3 Ensure TRUSTWORTHY is off', results[1]), item(0, '2.3 Ensure TRUSTWORTHY is off', results[1]),
    item(0, '3.1 Sysadmin users', 'FAILED', sysadmins(name)), item(0, '4.1 Ensure CLR disabled', results[2])];
  const xml = `<?xml version="1.0" ?><NessusClientData_v2 xmlns:cm="http://www.nessus.org/cm"><Policy><Preferences><PluginsPreferences></PluginsPreferences></Preferences></Policy><Report name="SQL all" xmlns:cm="http://www.nessus.org/cm">` +
    host('sql01', '10.6.0.1', [...run('MSSQL$SALES', ['PASSED', 'FAILED', 'FAILED']), ...run('MSSQL$HR', ['PASSED', 'FAILED', 'PASSED'])]) +
    host('sql02', '10.6.0.2', [item(0, '3.1 Sysadmin users', 'FAILED', sysadmins('MSSQLSERVER')), item(0, '5.1 OS audit setting', 'PASSED')]) +
    host('sql03', '10.6.0.3', [item(0, '3.1 Sysadmin users', 'FAILED', sysadmins('MSSQL$A') + sysadmins('MSSQL$B')), item(0, '2.1 Ensure xp_cmdshell disabled', 'PASSED')]) +
    host('sql05', '10.6.0.5', [authItem(1433)]) +
    '</Report></NessusClientData_v2>';
  const src = nessusSource('sql_all.nessus', xml);
  const [scan] = await W.send({ type: 'scan', files: [{ id: 1, file: src.file }] });
  eq(scan.dbType, 'Microsoft SQL Server', 'scan: type detected (audit file / instance accounts)');
  const cols = [...scan.headers, 'Database Type', 'Database'];
  const opts = { format: 'xlsx', mode: 'compliance', addSource: false, authPlugins: ['104410'] };
  let d = await merge([src], cols, { ...opts, dbMode: 'none', identity: 'host', dedupe: 'key' });
  eq(d.stats.duplicates, 6, 'without identification: HR\'s rows (and per-database repeats) removed as duplicates of SALES - the reported problem');
  d = await merge([src], cols, { ...opts, dbMode: 'auto', dedupe: 'key' });
  eq([d.stats.duplicates, d.stats.compliance], [0, [5, 9, 0, 0]], 'database mode: nothing removed within the report');
  const x = await readXlsx(d.blob);
  const f = x.sheets.Findings;
  const rowsOf = name => (f.match(new RegExp(`>${name.replace(/[$/]/g, '\\$&')}<`, 'g')) || []).length;
  eq([rowsOf('SALES'), rowsOf('HR'), rowsOf('MSSQLSERVER')], [5, 5, 2], 'port-0 rows: each audit run gets its instance, repeats inside a run don\'t split it');
  const dbs = cellTexts(x.sheets.Databases);
  eq(dbs.includes('A / B'), true, 'two instances named in one run shown as such, not guessed');
  eq(dbs.includes('InstanceName'), false, 'placeholder text in descriptions ignored');
  eq(dbs.filter(t => t === 'Microsoft SQL Server').length >= 4, true, 'type applied host-wide to port-0 rows');
  eq(d.stats.authHosts, 1, 'auth failure (port 1433) reported');
  eq(cellTexts(x.sheets.Sources).some(t => /HR/.test(t) && /SALES/.test(t)), true, 'Sources lists the instances found');
  // Inconsistent runs (3 runs, 2 names) are not applied.
  const bad = nessusSource('bad.nessus', xml.replace(host('sql02', '10.6.0.2', [item(0, '3.1 Sysadmin users', 'FAILED', sysadmins('MSSQLSERVER')), item(0, '5.1 OS audit setting', 'PASSED')]),
    host('sql06', '10.6.0.6', [...run('MSSQL$X', ['PASSED', 'PASSED', 'PASSED']), ...run('MSSQL$Y', ['PASSED', 'PASSED', 'PASSED']), item(0, '1.1 Ensure xp_cmdshell disabled', 'PASSED')])));
  d = await merge([bad], cols, { ...opts, dbMode: 'auto', dedupe: 'exact' });
  eq(cellTexts((await readXlsx(d.blob)).sheets.Databases).includes('X / Y'), true, 'runs that don\'t match names one-to-one fall back to "X / Y"');
}

section('duplicates in database mode');
{
  const xml = rows => `<?xml version="1.0" ?><NessusClientData_v2 xmlns:cm="http://www.nessus.org/cm"><Report name="r" xmlns:cm="http://www.nessus.org/cm"><ReportHost name="my01"><HostProperties><tag name="host-ip">10.8.0.1</tag></HostProperties>` +
    rows.map(r => `<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="33814" pluginName="Database Compliance Checks" pluginFamily="Policy Compliance"><cm:compliance-check-name>${r}</cm:compliance-check-name><cm:compliance-result>PASSED</cm:compliance-result><cm:compliance-audit-file>CIS_MySQL_8.audit</cm:compliance-audit-file><risk_factor>None</risk_factor></ReportItem>`).join('') +
    '</ReportHost></Report></NessusClientData_v2>';
  // Two unnamed MySQL databases in one scan give identical rows.
  const one = nessusSource('mysql.nessus', xml(['1.1 a', '1.2 b', '1.1 a', '1.2 b']));
  const cols = [...NESSUS_COLUMNS_FOR_TESTS(), 'Database Type', 'Database'];
  for (const dedupe of ['exact', 'key']) {
    const d = await merge([one], cols, { format: 'csv', mode: 'compliance', dbMode: 'auto', dedupe });
    eq([d.stats.duplicates, d.stats.rowsOut], [0, 4], `${dedupe}: identical rows within one report are kept`);
  }
  const d = await merge([one, { ...one, name: 'mysql-again.nessus' }], cols, { format: 'csv', mode: 'compliance', dbMode: 'auto', dedupe: 'exact', addSource: false });
  eq(d.stats.rowsOut, 8, 'unnamed databases in different reports are kept apart (cannot prove they are the same)');
  const named = nessusSource('ora.nessus', `<?xml version="1.0" ?><NessusClientData_v2 xmlns:cm="http://www.nessus.org/cm"><Policy><Preferences><PluginsPreferences><item><pluginName>Database settings</pluginName><pluginId>33815</pluginId><fullName>x</fullName><preferenceName>Database SID :</preferenceName><preferenceType>entry</preferenceType><preferenceValues></preferenceValues><selectedValue>LEREG</selectedValue></item></PluginsPreferences></Preferences></Policy>` + xml(['1.1 a', '1.2 b']).slice(xml(['1.1 a']).indexOf('<Report ')));
  const twice = await merge([named, { ...named, name: 'ora-again.nessus' }], cols, { format: 'csv', mode: 'compliance', dbMode: 'auto', dedupe: 'exact', addSource: false });
  eq([twice.stats.duplicates, twice.stats.rowsOut], [2, 2], 'the same named database in a later report is de-duplicated');
}

section('other database types');
{
  const one = (svc, port, policyType) => `<?xml version="1.0" ?><NessusClientData_v2 xmlns:cm="http://www.nessus.org/cm"><Policy><Preferences><PluginsPreferences>` +
    (policyType ? `<item><pluginName>Database settings</pluginName><pluginId>33815</pluginId><fullName>x</fullName><preferenceName>DB Type :</preferenceName><preferenceType>radio</preferenceType><preferenceValues></preferenceValues><selectedValue>${policyType}</selectedValue></item>` : '') +
    `</PluginsPreferences></Preferences></Policy><Report name="r" xmlns:cm="http://www.nessus.org/cm"><ReportHost name="h1"><HostProperties><tag name="host-ip">10.7.0.1</tag></HostProperties>` +
    `<ReportItem port="${port}" svc_name="${svc}" protocol="tcp" severity="0" pluginID="33814" pluginName="Database Compliance Checks" pluginFamily="Policy Compliance"><cm:compliance-check-name>1.1 c</cm:compliance-check-name><cm:compliance-result>PASSED</cm:compliance-result><risk_factor>None</risk_factor></ReportItem>` +
    '</ReportHost></Report></NessusClientData_v2>';
  const cases = [['db2.nessus', one('db2', 50000)], ['mysql.nessus', one('www', 3306)], ['pg.nessus', one('unknown', 9999, 'PostgreSQL')], ['mongo.nessus', one('mongodb', 27017)]];
  const sources = cases.map(([n, t]) => nessusSource(n, t));
  const d = await merge(sources, [...NESSUS_COLUMNS_FOR_TESTS(), 'Database Type', 'Database'], { format: 'xlsx', mode: 'compliance', dbMode: 'auto', dedupe: 'key' });
  const types = cellTexts((await readXlsx(d.blob)).sheets.Databases);
  eq(['IBM DB2', 'MySQL', 'PostgreSQL', 'MongoDB'].every(t => types.includes(t)), true, 'DB2 (service), MySQL (port), PostgreSQL (policy), MongoDB (service)');
  eq(d.stats.uniqueHosts, 4, 'same host and IP, four databases');
}

// ---------------------------------------------------------------------------
section('damaged copy of merge-worker.js');
{
  const damaged = loadWorker(SOURCE.replace('\\uFFFE\\uFFFF]/g', '  ]/g'));
  const msgs = await damaged.send({ type: 'merge', sources: [], columns: ['A'], options: { format: 'csv', rules: [] } });
  eq(/damaged/.test((msgs.find(m => m.type === 'error') || {}).message || ''), true, 'refuses to run and asks for a fresh download');
}

console.log(failures ? `\n${failures} FAILED, ${passes} passed` : `\nALL ${passes} CHECKS PASSED`);
process.exitCode = failures ? 1 : 0;
