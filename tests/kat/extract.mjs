// Regenerates the ML-KEM known-answer files in this directory from a checkout
// of https://github.com/usnistgov/ACVP-Server (gen-val/json-files).
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
