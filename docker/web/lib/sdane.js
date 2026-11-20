'use strict';

// Stateless DANE (HIP-17): two certificate extensions that carry the proofs a
// client needs to check a site's TLSA record against the Handshake blockchain,
// without any DNS lookups. Browsers and DANE proxies ignore them; Stateless DANE
// clients (SANE, Dit's checker) read them.
//
// - Urkel proof (OID ...1620): the TLD's on-chain state, with its DS records.
//   Fetched from a public proof service; clients verify it against tree roots
//   they synced themselves, so the service only has to be available.
// - DNSSEC chain (OID ...1621): port, lifetime, then the TLSA set, the zone's
//   DNSKEY set and the zone's DS set, each with its signatures, in DNS wire
//   format. Castell builds it from the site's DNS host (the nameserver set in
//   Settings) and checks every signature first. The public services build it
//   with a recursive resolver, which fails for some hosts (Yeil, Nov 2026).
const crypto = require('crypto');
const dns = require('./dns');

const OID_URKEL = '1.3.6.1.4.1.54392.5.1620';
const OID_DNSSEC = '1.3.6.1.4.1.54392.5.1621';
const SERVICES = (process.env.CASTELL_SDANE_SERVICES || 'https://sdaneproofs.htools.work,https://sdaneproofs.woodburn.au')
  .split(',').map(s => s.trim().replace(/\/+$/, '')).filter(Boolean);
const PORT = 443;
const HOUR = 60 * 60 * 1000;
// Proofs are tied to a tree root that changes every ~6 hours, and clients only
// accept roots from the last one to two weeks: once a day is plenty.
const REFRESH_EVERY = 24 * HOUR;
// After a failure, wait this long before trying again (the old certificate stays).
const RETRY_AFTER = HOUR;

const {TYPES} = dns;

// A failure with a reason the site page can show as is.
class ProofError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

const tldOf = name => name.split('.').pop();
const u16 = n => Buffer.from([n >> 8, n & 0xff]);

// ---------- Urkel proof ----------

async function fetchUrkel(tld, {services = SERVICES, fetchImpl = fetch} = {}) {
  const problems = [];
  for (const service of services) {
    try {
      const res = await fetchImpl(`${service}/proofs/${encodeURIComponent(tld)}?urkel`, {signal: AbortSignal.timeout(30000)});
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
      const hex = String(body.urkel || '').toLowerCase();
      // 1 byte proof count (at least one), then per proof a 32-byte root + the proof
      if (!/^([0-9a-f]{2})+$/.test(hex) || hex.length < 66 || hex.startsWith('00')) throw new Error('not an Urkel proof');
      return {hex, service: new URL(service).host};
    } catch (e) {
      problems.push(`${new URL(service).host}: ${e.message}`);
    }
  }
  throw new ProofError('urkel', `No proof service returned the on-chain proof for ${tld} (${problems.join('; ')}).`);
}

// ---------- DNS wire helpers ----------

function nameWire(name) {
  const parts = name ? name.split('.').map(label => {
    const bytes = Buffer.from(label, 'latin1');
    return Buffer.concat([Buffer.from([bytes.length]), bytes]);
  }) : [];
  return Buffer.concat([...parts, Buffer.from([0])]);
}

function rrWire({name, type, ttl, rdata}) {
  const head = Buffer.alloc(10);
  head.writeUInt16BE(type, 0);
  head.writeUInt16BE(1, 2); // class IN
  head.writeUInt32BE(ttl, 4);
  head.writeUInt16BE(rdata.length, 8);
  return Buffer.concat([nameWire(name), head, rdata]);
}

// RFC 4034 appendix B
function keyTag(dnskey) {
  let ac = 0;
  for (let i = 0; i < dnskey.length; i++) ac += i & 1 ? dnskey[i] : dnskey[i] << 8;
  return (ac + ((ac >> 16) & 0xffff)) & 0xffff;
}

const dsDigest = (owner, dnskey) => crypto.createHash('sha256').update(Buffer.concat([nameWire(owner), dnskey])).digest();

// DS rdata: key tag, algorithm, digest type 2 (SHA-256), digest
const dsRdata = (owner, dnskey) => Buffer.concat([u16(keyTag(dnskey)), Buffer.from([dnskey[3], 2]), dsDigest(owner, dnskey)]);

function parseRrsig(rdata) {
  let off = 18;
  const labels = [];
  while (rdata[off] !== 0) {
    if (rdata[off] === undefined || rdata[off] > 63) throw new Error('malformed RRSIG');
    labels.push(rdata.toString('latin1', off + 1, off + 1 + rdata[off]).toLowerCase());
    off += rdata[off] + 1;
  }
  return {
    typeCovered: rdata.readUInt16BE(0),
    algorithm: rdata[2],
    labels: rdata[3],
    originalTtl: rdata.readUInt32BE(4),
    expiration: rdata.readUInt32BE(8),
    inception: rdata.readUInt32BE(12),
    keyTag: rdata.readUInt16BE(16),
    signer: labels.join('.'),
    signedPart: rdata.subarray(0, off + 1),
    signature: rdata.subarray(off + 1),
  };
}

const b64url = buf => Buffer.from(buf).toString('base64url');

// A DNSKEY's public key, for the algorithms Castell checks
function publicKey(dnskey) {
  const algorithm = dnskey[3];
  const key = dnskey.subarray(4);
  if (algorithm === 13 || algorithm === 14) {
    const size = algorithm === 13 ? 32 : 48;
    return {
      key: crypto.createPublicKey({key: {kty: 'EC', crv: algorithm === 13 ? 'P-256' : 'P-384', x: b64url(key.subarray(0, size)), y: b64url(key.subarray(size))}, format: 'jwk'}),
      hash: algorithm === 13 ? 'sha256' : 'sha384',
      dsaEncoding: 'ieee-p1363',
    };
  }
  if (algorithm === 8 || algorithm === 10) {
    const long = key[0] === 0;
    const expLength = long ? key.readUInt16BE(1) : key[0];
    const start = long ? 3 : 1;
    return {
      key: crypto.createPublicKey({key: {kty: 'RSA', e: b64url(key.subarray(start, start + expLength)), n: b64url(key.subarray(start + expLength))}, format: 'jwk'}),
      hash: algorithm === 8 ? 'sha256' : 'sha512',
    };
  }
  if (algorithm === 15) {
    return {key: crypto.createPublicKey({key: {kty: 'OKP', crv: 'Ed25519', x: b64url(key)}, format: 'jwk'}), hash: null};
  }
  throw new Error(`DNSSEC algorithm ${algorithm} is not supported`);
}

// RFC 4034 3.1.8.1: is this RRset signed by sig, made by one of keys (owned by
// signer), and valid now? Returns null when it is, else the reason.
function checkSignature(rrset, sig, keys, now) {
  const s = parseRrsig(sig.rdata);
  const seconds = Math.floor(now / 1000);
  if (seconds < s.inception) return 'the signature is not valid yet';
  if (seconds > s.expiration) return 'the signature has expired';
  const key = keys.find(k => k.name === s.signer && k.rdata[3] === s.algorithm && keyTag(k.rdata) === s.keyTag);
  if (!key) return `no key with tag ${s.keyTag} signs it`;
  const owner = rrset[0].name;
  const ownerLabels = owner.split('.');
  // Signed through a wildcard: the canonical owner is *.<the last `labels` labels>
  const signedOwner = s.labels < ownerLabels.length ? ['*', ...ownerLabels.slice(-s.labels)].join('.') : owner;
  const canonical = rrset
    .map(r => rrWire({name: signedOwner, type: r.type, ttl: s.originalTtl, rdata: r.rdata}))
    .sort((a, b) => Buffer.compare(a, b));
  const data = Buffer.concat([s.signedPart, ...canonical]);
  try {
    const pub = publicKey(key.rdata);
    const ok = crypto.verify(pub.hash, data, pub.dsaEncoding ? {key: pub.key, dsaEncoding: pub.dsaEncoding} : pub.key, s.signature);
    return ok ? null : 'the signature does not match';
  } catch (e) {
    return e.message;
  }
}

// ---------- DNSSEC chain ----------

async function buildDnssecChain(name, {server, urkel, query = dns.queryRecords, now = Date.now()}) {
  const tld = tldOf(name);
  const tlsaName = `_${PORT}._tcp.${name}`;
  const tlsaAnswer = await query(server, tlsaName, 'TLSA');
  const tlsa = tlsaAnswer.records.filter(r => r.type === TYPES.TLSA && r.name === tlsaName);
  if (tlsaAnswer.rcode === 'REFUSED') {
    throw new ProofError('not-hosted', `${server} doesn't host the ${tld} zone. Check the DNS server in Castell's settings.`);
  }
  if (!tlsa.length) {
    throw new ProofError('no-tlsa', `${server} has no TLSA record for ${tlsaName} (${tlsaAnswer.rcode}). Publish it first.`);
  }
  const tlsaSigs = tlsaAnswer.records.filter(r => r.type === TYPES.RRSIG && r.name === tlsaName && r.rdata.readUInt16BE(0) === TYPES.TLSA);

  const keyAnswer = await query(server, tld, 'DNSKEY');
  const keys = keyAnswer.records.filter(r => r.type === TYPES.DNSKEY && r.name === tld);
  if (!keys.length) throw new ProofError('no-dnskey', `${server} returned no DNSKEY records for ${tld}, so the zone isn't signed.`);
  const keySigs = keyAnswer.records.filter(r => r.type === TYPES.RRSIG && r.name === tld && r.rdata.readUInt16BE(0) === TYPES.DNSKEY);

  // The trust anchor: the DS records proven on the Handshake chain. A key is
  // anchored when the digest of its DS record is in the Urkel proof.
  const anchored = keys.filter(k => k.rdata.readUInt16BE(0) & 1 && urkel.includes(dsDigest(tld, k.rdata)));
  if (!anchored.length) {
    throw new ProofError('ds-mismatch', `None of ${tld}'s keys matches the DS record on the Handshake chain. Check the DS record in Bob Wallet.`);
  }

  const reasons = [];
  const goodKeySigs = keySigs.filter(sig => {
    const reason = checkSignature(keys, sig, anchored, now);
    if (reason) reasons.push(reason);
    return !reason;
  });
  if (!goodKeySigs.length) {
    throw new ProofError('bad-signature', `${tld}'s keys aren't validly signed by a key on the Handshake chain (${reasons.join('; ') || 'no signatures'}).`);
  }

  if (tlsaSigs.some(sig => parseRrsig(sig.rdata).signer !== tld)) {
    throw new ProofError('delegated', `${name} is in its own zone below ${tld}. Castell builds proofs only for names in the ${tld} zone.`);
  }
  reasons.length = 0;
  const goodTlsaSigs = tlsaSigs.filter(sig => {
    const reason = checkSignature(tlsa, sig, keys, now);
    if (reason) reasons.push(reason);
    return !reason;
  });
  if (!goodTlsaSigs.length) {
    throw new ProofError('bad-signature', `The TLSA record isn't validly signed by ${tld}'s keys (${reasons.join('; ') || 'no signatures'}).`);
  }

  const ds = anchored.map(k => ({name: tld, type: TYPES.DS, ttl: k.ttl, rdata: dsRdata(tld, k.rdata)}));
  const records = [...tlsa, ...goodTlsaSigs, ...keys, ...goodKeySigs, ...ds];
  const blob = Buffer.concat([u16(PORT), u16(0), ...records.map(rrWire)]);
  const expires = Math.min(...[...goodTlsaSigs, ...goodKeySigs].map(sig => parseRrsig(sig.rdata).expiration));
  return {hex: blob.toString('hex'), signaturesExpire: new Date(expires * 1000).toISOString()};
}

// Both proofs for a site, or a ProofError saying what's missing.
async function fetchProofs(name, {dnsServer, services, fetchImpl, query, now = Date.now()} = {}) {
  const urkel = await fetchUrkel(tldOf(name), {services, fetchImpl});
  const chain = await buildDnssecChain(name, {server: dnsServer, urkel: Buffer.from(urkel.hex, 'hex'), query, now});
  return {
    urkel: urkel.hex,
    dnssec: chain.hex,
    service: urkel.service,
    dnsServer,
    signaturesExpire: chain.signaturesExpire,
    fetchedAt: new Date(now).toISOString(),
  };
}

// ---------- certificate ----------

// The openssl config that adds both proofs to a certificate. `DER:<hex>` puts
// the bytes verbatim as the extension's value; both extensions are non-critical.
function opensslConfig(name, proofs) {
  return [
    '[req]',
    'distinguished_name = dn',
    'prompt = no',
    '[dn]',
    `CN = ${name}`,
    '[ext]',
    `subjectAltName = DNS:${name},DNS:*.${name}`,
    `${OID_URKEL} = DER:${proofs.urkel}`,
    `${OID_DNSSEC} = DER:${proofs.dnssec}`,
    '',
  ].join('\n');
}

function oidBytes(oid) {
  const parts = oid.split('.').map(Number);
  const out = [40 * parts[0] + parts[1]];
  for (const n of parts.slice(2)) {
    const base128 = [n & 0x7f];
    for (let v = Math.floor(n / 128); v > 0; v = Math.floor(v / 128)) base128.unshift((v & 0x7f) | 0x80);
    out.push(...base128);
  }
  return Buffer.from([0x06, out.length, ...out]);
}

// A DER length at off: {length, start of the value}
function derLength(buf, off) {
  const first = buf[off];
  if (first < 0x80) return {length: first, start: off + 1};
  const count = first & 0x7f;
  let length = 0;
  for (let i = 1; i <= count; i++) length = length * 256 + buf[off + i];
  return {length, start: off + 1 + count};
}

// The proofs inside a certificate (PEM or DER): {urkel, dnssec}, hex or null.
function readProofs(cert) {
  const der = Buffer.isBuffer(cert) && cert[0] === 0x30 ? cert : new crypto.X509Certificate(cert).raw;
  const value = oid => {
    const at = der.indexOf(oidBytes(oid));
    if (at < 0) return null;
    let off = at + oidBytes(oid).length;
    if (der[off] === 0x01) off += 3; // critical flag
    if (der[off] !== 0x04) return null;
    const {length, start} = derLength(der, off + 1);
    return der.subarray(start, start + length).toString('hex');
  };
  return {urkel: value(OID_URKEL), dnssec: value(OID_DNSSEC)};
}

// ---------- when to refresh ----------

// What the daily job should do for a site:
//   'none'    nothing (off and plain, fresh proofs, or waiting to retry)
//   'refresh' fetch new proofs and reissue the certificate with them
//   'plain'   proofs were turned off: reissue the certificate without them
function refreshDecision(sdane, certHasProofs, now = Date.now()) {
  const enabled = Boolean(sdane && sdane.enabled);
  if (!enabled) return certHasProofs ? 'plain' : 'none';
  const since = time => (time ? now - Date.parse(time) : Infinity);
  if (sdane.lastError && since(sdane.lastAttempt) < RETRY_AFTER) return 'none';
  if (certHasProofs && since(sdane.fetchedAt) < REFRESH_EVERY) return 'none';
  return 'refresh';
}

module.exports = {
  OID_URKEL, OID_DNSSEC, REFRESH_EVERY, RETRY_AFTER, ProofError,
  fetchUrkel, buildDnssecChain, fetchProofs, opensslConfig, readProofs, refreshDecision,
  // for tests
  keyTag, dsRdata, rrWire, parseRrsig, checkSignature,
};
