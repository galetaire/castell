'use strict';

const assert = require('assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {test} = require('node:test');
const certs = require('../lib/certs');
const sdane = require('../lib/sdane');
const {makeZone} = require('./zone');

const HOUR = 60 * 60 * 1000;
const ago = ms => new Date(Date.now() - ms).toISOString();

// ---------- openssl config ----------

test('openssl config puts both proofs in as raw extension values', () => {
  assert.equal(sdane.opensslConfig('mysite', {urkel: '01aa', dnssec: '01bb0000'}), [
    '[req]',
    'distinguished_name = dn',
    'prompt = no',
    '[dn]',
    'CN = mysite',
    '[ext]',
    'subjectAltName = DNS:mysite,DNS:*.mysite',
    '1.3.6.1.4.1.54392.5.1620 = DER:01aa',
    '1.3.6.1.4.1.54392.5.1621 = DER:01bb0000',
    '',
  ].join('\n'));
});

// ---------- refresh decision ----------

test('refresh decision: off', () => {
  assert.equal(sdane.refreshDecision(undefined, false), 'none');
  assert.equal(sdane.refreshDecision({enabled: false}, false), 'none');
  // turned off while the certificate still carries proofs: reissue it plain
  assert.equal(sdane.refreshDecision({enabled: false}, true), 'plain');
});

test('refresh decision: fresh proofs are kept for a day', () => {
  assert.equal(sdane.refreshDecision({enabled: true, fetchedAt: ago(2 * HOUR)}, true), 'none');
  assert.equal(sdane.refreshDecision({enabled: true, fetchedAt: ago(25 * HOUR)}, true), 'refresh');
});

test('refresh decision: just turned on, or the certificate lost its proofs', () => {
  assert.equal(sdane.refreshDecision({enabled: true}, false), 'refresh');
  assert.equal(sdane.refreshDecision({enabled: true, fetchedAt: ago(2 * HOUR)}, false), 'refresh');
});

test('refresh decision: after a failure, wait an hour before trying again', () => {
  const failed = minutes => ({enabled: true, fetchedAt: ago(30 * HOUR), lastAttempt: ago(minutes * 60 * 1000), lastError: 'no TLSA record'});
  assert.equal(sdane.refreshDecision(failed(10), true), 'none');
  assert.equal(sdane.refreshDecision(failed(90), true), 'refresh');
  // a failure on the very first try (no TLSA record yet) waits the same way
  assert.equal(sdane.refreshDecision({enabled: true, lastAttempt: ago(5 * 60 * 1000), lastError: 'no TLSA record'}, false), 'none');
});

// ---------- DNSSEC chain ----------

// The records in a chain blob: [{name, type}]
function chainRecords(hex) {
  const b = Buffer.from(hex, 'hex');
  const out = [];
  let off = 4;
  while (off < b.length) {
    const labels = [];
    while (b[off] !== 0) {
      labels.push(b.toString('latin1', off + 1, off + 1 + b[off]));
      off += b[off] + 1;
    }
    off += 1;
    const type = b.readUInt16BE(off);
    off += 10 + b.readUInt16BE(off + 8);
    out.push({name: labels.join('.'), type});
  }
  return out;
}

test('chain: TLSA, its signature, the zone keys, their signature and the DS', async () => {
  const zone = makeZone('mysite');
  zone.tlsaFor('mysite');
  const chain = await sdane.buildDnssecChain('mysite', {server: 'ns', urkel: Buffer.from(zone.urkel, 'hex'), query: zone.query});
  assert.ok(chain.hex.startsWith('01bb0000'), 'port 443, lifetime 0');
  assert.deepEqual(chainRecords(chain.hex), [
    {name: '_443._tcp.mysite', type: 52},
    {name: '_443._tcp.mysite', type: 46},
    {name: 'mysite', type: 48},
    {name: 'mysite', type: 46},
    {name: 'mysite', type: 43},
  ]);
  assert.ok(Date.parse(chain.signaturesExpire) > Date.now() + 6 * 24 * HOUR);
});

test('chain: a subdomain in the same zone', async () => {
  const zone = makeZone('mysite');
  zone.tlsaFor('blog.mysite');
  const chain = await sdane.buildDnssecChain('blog.mysite', {server: 'ns', urkel: Buffer.from(zone.urkel, 'hex'), query: zone.query});
  assert.equal(chainRecords(chain.hex)[0].name, '_443._tcp.blog.mysite');
});

test('chain: no TLSA record published', async () => {
  const zone = makeZone('mysite');
  await assert.rejects(
    sdane.buildDnssecChain('mysite', {server: 'ns', urkel: Buffer.from(zone.urkel, 'hex'), query: zone.query}),
    e => e.code === 'no-tlsa' && /Publish it first/.test(e.message));
});

test('chain: the nameserver does not host the zone', async () => {
  const zone = makeZone('mysite');
  await assert.rejects(
    sdane.buildDnssecChain('othersite', {server: 'ns', urkel: Buffer.from(zone.urkel, 'hex'), query: zone.query}),
    e => e.code === 'not-hosted');
});

test('chain: the on-chain DS does not match the zone keys', async () => {
  const zone = makeZone('mysite');
  zone.tlsaFor('mysite');
  const otherUrkel = Buffer.from(makeZone('mysite').urkel, 'hex');
  await assert.rejects(
    sdane.buildDnssecChain('mysite', {server: 'ns', urkel: otherUrkel, query: zone.query}),
    e => e.code === 'ds-mismatch');
});

test('chain: a TLSA record changed after signing is refused', async () => {
  const zone = makeZone('mysite');
  zone.tlsaFor('mysite');
  zone.records['_443._tcp.mysite'][0].rdata[5] ^= 0xff;
  await assert.rejects(
    sdane.buildDnssecChain('mysite', {server: 'ns', urkel: Buffer.from(zone.urkel, 'hex'), query: zone.query}),
    e => e.code === 'bad-signature' && /does not match/.test(e.message));
});

test('chain: an expired signature is refused', async () => {
  const zone = makeZone('mysite');
  const now = Math.floor(Date.now() / 1000);
  const rdata = Buffer.concat([Buffer.from([3, 1, 1]), Buffer.alloc(32, 7)]);
  zone.add('_443._tcp.mysite', [{name: '_443._tcp.mysite', type: 52, ttl: 300, rdata}], {inception: now - 20 * 86400, expiration: now - 86400});
  await assert.rejects(
    sdane.buildDnssecChain('mysite', {server: 'ns', urkel: Buffer.from(zone.urkel, 'hex'), query: zone.query}),
    e => e.code === 'bad-signature' && /expired/.test(e.message));
});

test('proofs: a failing proof service is reported, not thrown blindly', async () => {
  const fetchImpl = async () => ({ok: false, status: 500, json: async () => ({error: 'boom'})});
  await assert.rejects(
    sdane.fetchProofs('mysite', {dnsServer: 'ns', services: ['https://a.example', 'https://b.example'], fetchImpl}),
    e => e.code === 'urkel' && /a\.example: boom; b\.example: boom/.test(e.message));
});

test('proofs: both, from a service and the zone', async () => {
  const zone = makeZone('mysite');
  zone.tlsaFor('mysite');
  const fetchImpl = async url => ({ok: true, status: 200, json: async () => ({urkel: url.includes('/proofs/mysite?urkel') ? zone.urkel : ''})});
  const proofs = await sdane.fetchProofs('mysite', {dnsServer: 'ns', services: ['https://proofs.example'], fetchImpl, query: zone.query});
  assert.equal(proofs.urkel, zone.urkel);
  assert.equal(proofs.service, 'proofs.example');
  assert.ok(proofs.dnssec.startsWith('01bb0000'));
});

// ---------- certificates ----------

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'castell-test-'));
}

test('certificate with proofs carries both extensions, byte for byte', async () => {
  const dir = tempDir();
  try {
    const key = path.join(dir, 'key.pem');
    await certs.generateKey(key);
    const proofs = {urkel: '01' + 'ab'.repeat(40), dnssec: '01bb0000' + 'cd'.repeat(300)};
    await certs.issueCert('mysite', key, path.join(dir, 'cert.pem'), proofs);
    assert.deepEqual(sdane.readProofs(fs.readFileSync(path.join(dir, 'cert.pem'))), proofs);
    // same key: the TLSA record doesn't change
    const cert = new (require('crypto').X509Certificate)(fs.readFileSync(path.join(dir, 'cert.pem')));
    assert.equal(certs.tlsaFromCert(cert), certs.tlsaFromKeyFile(key));
    assert.match(cert.subjectAltName, /DNS:mysite, DNS:\*\.mysite/);
    assert.deepEqual(fs.readdirSync(dir).sort(), ['cert.pem', 'key.pem'], 'no config file left behind');
  } finally {
    fs.rmSync(dir, {recursive: true, force: true});
  }
});

test('certificate without proofs: plain DANE, as before', async () => {
  const dir = tempDir();
  try {
    const key = path.join(dir, 'key.pem');
    await certs.generateKey(key);
    await certs.issueCert('mysite', key, path.join(dir, 'cert.pem'));
    assert.deepEqual(sdane.readProofs(fs.readFileSync(path.join(dir, 'cert.pem'))), {urkel: null, dnssec: null});
    const cert = new (require('crypto').X509Certificate)(fs.readFileSync(path.join(dir, 'cert.pem')));
    assert.equal(cert.subject, 'CN=mysite');
    assert.match(cert.subjectAltName, /DNS:mysite, DNS:\*\.mysite/);
    assert.equal(certs.tlsaFromCert(cert), certs.tlsaFromKeyFile(key));
  } finally {
    fs.rmSync(dir, {recursive: true, force: true});
  }
});
