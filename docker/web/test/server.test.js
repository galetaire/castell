'use strict';

// The real Castell server, against a fake proof service and a fake DNS server
// (on loopback) that serves a signed test zone.
const assert = require('assert/strict');
const {spawn} = require('child_process');
const dgram = require('dgram');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const {after, before, test} = require('node:test');
const sdane = require('../lib/sdane');
const {TYPES} = require('../lib/dns');
const {makeZone} = require('./zone');

const zone = makeZone('mysite');
zone.tlsaFor('mysite');
// blog.mysite gets no TLSA record

let serviceFails = false;
const service = http.createServer((req, res) => {
  const ok = !serviceFails && req.url === '/proofs/mysite?urkel';
  res.writeHead(ok ? 200 : 500, {'Content-Type': 'application/json'});
  res.end(JSON.stringify(ok ? {urkel: zone.urkel} : {error: 'service down'}));
});

// Answers questions from the zone, as an authoritative server would
const nameserver = dgram.createSocket('udp4');
nameserver.on('message', async (msg, peer) => {
  let off = 12;
  const labels = [];
  while (msg[off] !== 0) {
    labels.push(msg.toString('latin1', off + 1, off + 1 + msg[off]));
    off += msg[off] + 1;
  }
  const question = msg.subarray(12, off + 5);
  const type = Object.keys(TYPES).find(k => TYPES[k] === msg.readUInt16BE(off + 1));
  const {rcode, records} = await zone.query('ns', labels.join('.').toLowerCase(), type);
  const head = Buffer.alloc(12);
  msg.copy(head, 0, 0, 2);
  head.writeUInt16BE(0x8400 | {NOERROR: 0, NXDOMAIN: 3, REFUSED: 5}[rcode], 2);
  head.writeUInt16BE(1, 4);
  head.writeUInt16BE(records.length, 6);
  nameserver.send(Buffer.concat([head, question, ...records.map(sdane.rrWire)]), peer.port, peer.address);
});

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'castell-server-'));
const PORT = 40000 + Math.floor(Math.random() * 10000);
let server;

async function api(method, url, body) {
  const res = await fetch(`http://127.0.0.1:${PORT}/${url}`, {
    method,
    headers: {'X-Castell': '1', 'Content-Type': 'application/json'},
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error);
  return json;
}

const siteFile = (name, file) => path.join(dataDir, 'sites', name, file);
const servedProofs = site => sdane.readProofs(fs.readFileSync(siteFile(site.name, site.certFile)));

before(async () => {
  await new Promise(resolve => service.listen(0, '127.0.0.1', resolve));
  await new Promise(resolve => nameserver.bind(0, '127.0.0.1', resolve));
  server = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
    env: {...process.env, CASTELL_DATA: dataDir, PORT: String(PORT), CASTELL_SDANE_SERVICES: `http://127.0.0.1:${service.address().port}`},
    stdio: 'ignore',
  });
  for (let i = 0; i < 50; i++) {
    try {
      await fetch(`http://127.0.0.1:${PORT}/api/state`);
      break;
    } catch (e) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }
  await api('PUT', 'api/settings', {dnsServer: `127.0.0.1:${nameserver.address().port}`});
});

after(() => {
  server.kill();
  service.close();
  nameserver.close();
  fs.rmSync(dataDir, {recursive: true, force: true});
});

test('off by default: plain DANE, as before', async () => {
  const site = await api('POST', 'api/sites', {name: 'mysite'});
  assert.equal(site.sdane.enabled, false);
  assert.equal(site.sdane.inCertificate, false);
  assert.deepEqual(servedProofs(site), {urkel: null, dnssec: null});
  await new Promise(resolve => setTimeout(resolve, 1100)); // a new certificate name each second
  const renewed = await api('POST', 'api/sites/mysite/renew');
  assert.deepEqual(servedProofs(renewed), {urkel: null, dnssec: null});
  assert.match(fs.readFileSync(path.join(dataDir, 'Caddyfile'), 'utf8'), new RegExp(`tls /castell/sites/mysite/${renewed.certFile} /castell/sites/mysite/key.pem`));
});

test('turned on: the certificate carries the proofs, with the same key', async () => {
  const before = (await api('GET', 'api/state')).sites.find(s => s.name === 'mysite');
  await new Promise(resolve => setTimeout(resolve, 1100)); // a new certificate name each second
  const site = await api('PUT', 'api/sites/mysite/sdane', {enabled: true});
  assert.equal(site.sdane.inCertificate, true);
  assert.equal(site.sdane.lastError, null);
  assert.notEqual(site.certFile, before.certFile);
  assert.equal(site.tlsa, before.tlsa, 'same key, same TLSA record');
  const proofs = servedProofs(site);
  assert.equal(proofs.urkel, zone.urkel);
  assert.ok(proofs.dnssec.startsWith('01bb0000'));
  assert.ok(fs.existsSync(siteFile('mysite', 'proofs.json')));
  // a manual reissue keeps the proofs
  await new Promise(resolve => setTimeout(resolve, 1100));
  const renewed = await api('POST', 'api/sites/mysite/renew');
  assert.deepEqual(servedProofs(renewed), proofs);
});

test('a failed refresh keeps the certificate and shows the error', async () => {
  const before = (await api('GET', 'api/state')).sites.find(s => s.name === 'mysite');
  serviceFails = true;
  try {
    const site = await api('POST', 'api/sites/mysite/sdane/refresh');
    assert.equal(site.certFile, before.certFile, 'same certificate');
    assert.equal(site.sdane.inCertificate, true);
    assert.match(site.sdane.lastError, /service down/);
    assert.equal(site.sdane.fetchedAt, before.sdane.fetchedAt, 'the last good proofs are still the ones served');
  } finally {
    serviceFails = false;
  }
});

test('no TLSA record: nothing is reissued, and the reason is shown', async () => {
  const created = await api('POST', 'api/sites', {name: 'blog.mysite'});
  const site = await api('PUT', 'api/sites/blog.mysite/sdane', {enabled: true});
  assert.equal(site.certFile, created.certFile);
  assert.equal(site.sdane.inCertificate, false);
  assert.match(site.sdane.lastError, /no TLSA record for _443\._tcp\.blog\.mysite/);
});

test('turned off: the certificate is reissued without the proofs', async () => {
  await new Promise(resolve => setTimeout(resolve, 1100));
  const site = await api('PUT', 'api/sites/mysite/sdane', {enabled: false});
  assert.equal(site.sdane.enabled, false);
  assert.equal(site.sdane.inCertificate, false);
  assert.deepEqual(servedProofs(site), {urkel: null, dnssec: null});
  await assert.rejects(api('POST', 'api/sites/mysite/sdane/refresh'), /Turn on Stateless DANE proofs/);
});
