// Regenerates the ML-KEM and ML-DSA known-answer files in this directory from
// a checkout of https://github.com/usnistgov/ACVP-Server (gen-val/json-files).
// Usage: node tests/kat/extract.mjs <ACVP-Server checkout> <commit>
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const [root, commit = 'unknown'] = process.argv.slice(2);
if (!root) { console.error('usage: node extract.mjs <ACVP-Server checkout> [commit]'); process.exit(2); }
const load = (d) => JSON.parse(readFileSync(path.join(root, 'gen-val/json-files', d, 'internalProjection.json'), 'utf8'));
const keyGen = load('ML-KEM-keyGen-FIPS203');
const encDec = load('ML-KEM-encapDecap-FIPS203');
const here = path.dirname(new URL(import.meta.url).pathname);

function groups(j, set, fn) {
  return j.testGroups.filter((g) => g.parameterSet === set && (fn === undefined || g.function === fn));
}

function kats(set) {
  const lines = [];
  const kg = groups(keyGen, set).flatMap((g) => g.tests);
  const en = groups(encDec, set, 'encapsulation').flatMap((g) => g.tests);
  const de = groups(encDec, set, 'decapsulation').flatMap((g) => g.tests);
  lines.push(
    `# ${set} known-answer tests (FIPS 203)`,
    '# Source: NIST ACVP-Server, gen-val/json-files/{ML-KEM-keyGen-FIPS203,ML-KEM-encapDecap-FIPS203}',
    `#   https://github.com/usnistgov/ACVP-Server (commit ${commit})`,
    '# Extracted verbatim by tests/kat/extract.mjs. One record per line:',
    '#   keygen <tcId> <d> <z> <ek> <dk>',
    '#   encaps <tcId> <ek> <m> <c> <k>',
    '#   decaps <tcId> <dk> <c> <k>      (VAL group: includes modified-ciphertext',
    '#                                    cases, where k is the implicit-rejection key)',
    `# counts: keygen=${kg.length} encaps=${en.length} decaps=${de.length}`,
  );
  for (const t of kg) lines.push(`keygen ${t.tcId} ${t.d} ${t.z} ${t.ek} ${t.dk}`);
  for (const t of en) lines.push(`encaps ${t.tcId} ${t.ek} ${t.m} ${t.c} ${t.k}`);
  for (const t of de) lines.push(`decaps ${t.tcId} ${t.dk} ${t.c} ${t.k}`);
  return lines.join('\n') + '\n';
}

function keyChecks() {
  const lines = [
    '# ML-KEM input checks (FIPS 203 sections 7.2 and 7.3)',
    '# Source: NIST ACVP-Server, gen-val/json-files/ML-KEM-encapDecap-FIPS203',
    `#   https://github.com/usnistgov/ACVP-Server (commit ${commit})`,
    '# Extracted verbatim by tests/kat/extract.mjs. One record per line:',
    '#   ekcheck <set> <tcId> <pass|fail> <ek>',
    '#   dkcheck <set> <tcId> <pass|fail> <dk>',
  ];
  for (const set of ['ML-KEM-512', 'ML-KEM-768']) {
    for (const t of groups(encDec, set, 'encapsulationKeyCheck').flatMap((g) => g.tests))
      lines.push(`ekcheck ${set} ${t.tcId} ${t.testPassed ? 'pass' : 'fail'} ${t.ek}`);
    for (const t of groups(encDec, set, 'decapsulationKeyCheck').flatMap((g) => g.tests))
      lines.push(`dkcheck ${set} ${t.tcId} ${t.testPassed ? 'pass' : 'fail'} ${t.dk}`);
  }
  return lines.join('\n') + '\n';
}

writeFileSync(path.join(here, 'ml_kem_768_fips203.txt'), kats('ML-KEM-768'));
writeFileSync(path.join(here, 'ml_kem_keycheck_fips203.txt'), keyChecks());
// The 512 file predates this script; compare instead of overwriting.
const old = readFileSync(path.join(here, 'ml_kem_512_fips203.txt'), 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
const fresh = kats('ML-KEM-512').split('\n').filter((l) => l && !l.startsWith('#'));
console.log('ML-KEM-512 records match the committed file:', JSON.stringify(old) === JSON.stringify(fresh));

// ML-DSA-65 (FIPS 204). Pure ML-DSA only: the HashML-DSA groups (preHash) are
// skipped. Empty byte strings are written as '-' so every field is one token.
const dsaKeyGen = load('ML-DSA-keyGen-FIPS204');
const dsaSigGen = load('ML-DSA-sigGen-FIPS204');
const dsaSigVer = load('ML-DSA-sigVer-FIPS204');
const DSA = 'ML-DSA-65';
const hex = (s) => (s === '' ? '-' : s);
const ZERO_RND = '00'.repeat(32);

function dsaHeader(title, dirs, formats, counts) {
  return [
    `# ${DSA} ${title} (FIPS 204)`,
    `# Source: NIST ACVP-Server, gen-val/json-files/${dirs}`,
    `#   https://github.com/usnistgov/ACVP-Server (commit ${commit})`,
    '# Extracted verbatim by tests/kat/extract.mjs. One record per line:',
    ...formats.map((f) => `#   ${f}`),
    `# counts: ${counts}`,
  ];
}

// The interface a group exercises: external (pure ML-DSA, Algorithms 2 and 3,
// msg = M), internal (Algorithms 7 and 8, msg = M') or mu (Algorithms 7 and 8
// with mu supplied by the caller, msg = mu). Returns undefined for HashML-DSA.
function dsaInterface(g) {
  if (g.signatureInterface === 'external') return g.preHash === 'pure' ? 'external' : undefined;
  return g.externalMu ? 'mu' : 'internal';
}

function dsaGroups(j) {
  const kept = [];
  const skipped = [];
  for (const g of j.testGroups.filter((g) => g.parameterSet === DSA)) {
    for (const t of g.tests) if (t.deferred) throw new Error(`deferred test tg${g.tgId} tc${t.tcId}`);
    (dsaInterface(g) === undefined ? skipped : kept).push(g);
  }
  return { kept, skipped };
}

const skipNote = (skipped) =>
  `# Skipped: HashML-DSA (preHash) groups ${skipped.map((g) => `tg${g.tgId}`).join(', ') || 'none'}, ` +
  `${skipped.reduce((n, g) => n + g.tests.length, 0)} cases (out of scope)`;

function dsaKeyGenKats() {
  const tests = dsaKeyGen.testGroups.filter((g) => g.parameterSet === DSA).flatMap((g) => g.tests);
  const lines = dsaHeader('key generation known-answer tests', 'ML-DSA-keyGen-FIPS204', [
    'keygen <tcId> <xi> <pk> <sk>      (ML-DSA.KeyGen_internal, Algorithm 6)',
  ], `keygen=${tests.length}`);
  for (const t of tests) lines.push(`keygen ${t.tcId} ${t.seed} ${t.pk} ${t.sk}`);
  return lines.join('\n') + '\n';
}

function dsaSigGenKats() {
  const { kept, skipped } = dsaGroups(dsaSigGen);
  const lines = [];
  const counts = {};
  for (const g of kept) {
    const iface = dsaInterface(g);
    const mode = g.deterministic ? 'det' : 'hedged';
    const key = `${iface}/${mode}`;
    for (const t of g.tests) {
      const msg = iface === 'mu' ? t.mu : t.message;
      const ctx = iface === 'external' ? hex(t.context) : '-';
      const rnd = g.deterministic ? ZERO_RND : t.rnd;
      lines.push(`sign ${t.tcId} ${iface} ${mode} ${ctx} ${hex(msg)} ${rnd} ${t.pk} ${t.sk} ${t.signature}`);
      counts[key] = (counts[key] ?? 0) + 1;
    }
  }
  const head = dsaHeader('signature generation known-answer tests', 'ML-DSA-sigGen-FIPS204', [
    'sign <tcId> <interface> <det|hedged> <ctx> <msg> <rnd> <pk> <sk> <sig>',
    '  interface external: ML-DSA.Sign (Algorithm 2), msg is M, ctx is the context string',
    '  interface internal: ML-DSA.Sign_internal (Algorithm 7), msg is M\', ctx is -',
    '  interface mu:       Algorithm 7 with an external mu, msg is mu (64 bytes), ctx is -',
    '  det: rnd is 32 zero bytes (Algorithm 2 line 5, deterministic variant)',
    '  hedged: rnd is the 32-byte value from the ACVP record',
    '  - stands for the empty byte string',
  ], Object.entries(counts).map(([k, n]) => `${k}=${n}`).join(' '));
  return [...head, skipNote(skipped), ...lines].join('\n') + '\n';
}

function dsaSigVerKats() {
  const { kept, skipped } = dsaGroups(dsaSigVer);
  const lines = [];
  const counts = {};
  for (const g of kept) {
    const iface = dsaInterface(g);
    for (const t of g.tests) {
      const msg = iface === 'mu' ? t.mu : t.message;
      const ctx = iface === 'external' ? hex(t.context) : '-';
      const verdict = t.testPassed ? 'pass' : 'fail';
      lines.push(`verify ${t.tcId} ${iface} ${verdict} ${ctx} ${hex(msg)} ${t.pk} ${t.signature} ${t.reason}`);
      const key = `${iface}/${verdict}`;
      counts[key] = (counts[key] ?? 0) + 1;
    }
  }
  const head = dsaHeader('signature verification known-answer tests', 'ML-DSA-sigVer-FIPS204', [
    'verify <tcId> <interface> <pass|fail> <ctx> <msg> <pk> <sig> <reason...>',
    '  interface external: ML-DSA.Verify (Algorithm 3), msg is M, ctx is the context string',
    '  interface internal: ML-DSA.Verify_internal (Algorithm 8), msg is M\', ctx is -',
    '  interface mu:       Algorithm 8 with an external mu, msg is mu (64 bytes), ctx is -',
    '  reason: the ACVP reason text, verbatim, to the end of the line',
    '  - stands for the empty byte string',
  ], Object.entries(counts).map(([k, n]) => `${k}=${n}`).join(' '));
  return [...head, skipNote(skipped), ...lines].join('\n') + '\n';
}

writeFileSync(path.join(here, 'ml_dsa_65_keygen_fips204.txt'), dsaKeyGenKats());
writeFileSync(path.join(here, 'ml_dsa_65_siggen_fips204.txt'), dsaSigGenKats());
writeFileSync(path.join(here, 'ml_dsa_65_sigver_fips204.txt'), dsaSigVerKats());
