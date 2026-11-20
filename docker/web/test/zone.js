'use strict';

// A DNSSEC-signed test zone (ECDSA P-256, like Yeil's), to build and check
// Stateless DANE chains without the network.
const crypto = require('crypto');
const sdane = require('../lib/sdane');
const {TYPES} = require('../lib/dns');

const HOUR = 3600;

function nameWire(name) {
  return Buffer.concat([...name.split('.').map(l => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])), Buffer.from([0])]);
}

function makeZone(tld, {now = Date.now()} = {}) {
  const {privateKey, publicKey} = crypto.generateKeyPairSync('ec', {namedCurve: 'P-256'});
  const jwk = publicKey.export({format: 'jwk'});
  const pub = Buffer.concat([Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
  // flags 257 (zone key + secure entry point), protocol 3, algorithm 13
  const keyRdata = Buffer.concat([Buffer.from([1, 1, 3, 13]), pub]);
  const tag = sdane.keyTag(keyRdata);
  const seconds = Math.floor(now / 1000);

  // RFC 4034 3.1.8.1, signed by this zone's key
  function sign(rrset, {inception = seconds - HOUR, expiration = seconds + 7 * 24 * HOUR} = {}) {
    const owner = rrset[0].name;
    const head = Buffer.alloc(18);
    head.writeUInt16BE(rrset[0].type, 0);
    head[2] = 13;
    head[3] = owner.split('.').length;
    head.writeUInt32BE(rrset[0].ttl, 4);
    head.writeUInt32BE(expiration, 8);
    head.writeUInt32BE(inception, 12);
    head.writeUInt16BE(tag, 16);
    const signedPart = Buffer.concat([head, nameWire(tld)]);
    const canonical = rrset.map(r => sdane.rrWire(r)).sort((a, b) => Buffer.compare(a, b));
    const signature = crypto.sign('sha256', Buffer.concat([signedPart, ...canonical]), {key: privateKey, dsaEncoding: 'ieee-p1363'});
    return {name: owner, type: TYPES.RRSIG, ttl: rrset[0].ttl, rdata: Buffer.concat([signedPart, signature])};
  }

  const dnskey = {name: tld, type: TYPES.DNSKEY, ttl: 3600, rdata: keyRdata};
  const records = {};
  const add = (name, rrset, sigOptions) => {
    records[name] = [...(records[name] || []), ...rrset, sign(rrset, sigOptions)];
  };
  add(tld, [dnskey]);
  const tlsaFor = (name, hash = 'ab'.repeat(32)) => {
    const rdata = Buffer.concat([Buffer.from([3, 1, 1]), Buffer.from(hash, 'hex')]);
    add(`_443._tcp.${name}`, [{name: `_443._tcp.${name}`, type: TYPES.TLSA, ttl: 300, rdata}]);
  };

  // What a proof service returns for the TLD: an Urkel proof whose name state holds the DS
  const ds = sdane.dsRdata(tld, keyRdata);
  const urkel = Buffer.concat([Buffer.from([1]), crypto.randomBytes(32), Buffer.from('proof-nodes'), ds]).toString('hex');

  // A query function shaped like dns.queryRecords
  const query = async (server, name, type) => {
    if (!name.endsWith(tld)) return {rcode: 'REFUSED', records: []};
    const at = records[name] || [];
    const wanted = TYPES[type];
    const matching = at.filter(r => r.type === wanted || (r.type === TYPES.RRSIG && r.rdata.readUInt16BE(0) === wanted));
    return {rcode: at.length ? 'NOERROR' : 'NXDOMAIN', records: matching};
  };

  return {tld, keyRdata, records, urkel, query, sign, add, tlsaFor};
}

module.exports = {makeZone};
