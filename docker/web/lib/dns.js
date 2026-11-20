'use strict';

// Minimal DNS client for A and TLSA lookups. The server is either:
// - a nameserver, "host" or "host:port" (plain DNS over UDP, TCP if truncated).
//   Usually your DNS host's own nameserver (e.g. a.ns.yeil.org): it answers
//   authoritatively for your zone, so it shows exactly what you published.
// - a DNS-over-HTTPS URL, "https://..." (RFC 8484), e.g. a Handshake resolver.
const dgram = require('dgram');
const net = require('net');

const TYPES = {A: 1, DS: 43, RRSIG: 46, DNSKEY: 48, TLSA: 52, OPT: 41};
const RCODES = {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED'};
const TIMEOUT = 6000;

// recursive: ask a resolver to recurse (RD) and report DNSSEC validation (AD).
// Either way an EDNS record with the DO bit asks for signatures (RRSIG).
function encodeQuery(name, type, {recursive}) {
  const flags = recursive ? 0x0120 : 0;
  // ID 0, as RFC 8484 recommends; plain DNS gets a random one
  const id = recursive ? 0 : Math.floor(Math.random() * 0x10000);
  const parts = [Buffer.from([id >> 8, id & 0xff, flags >> 8, flags & 0xff, 0, 1, 0, 0, 0, 0, 0, 1])];
  for (const label of name.replace(/\.$/, '').split('.')) {
    const bytes = Buffer.from(label, 'ascii');
    parts.push(Buffer.from([bytes.length]), bytes);
  }
  parts.push(Buffer.from([0, type >> 8, type & 0xff, 0, 1]));
  // OPT: root name, type 41, UDP size 1232, extended rcode/version 0, DO bit, no options
  parts.push(Buffer.from([0, 0, TYPES.OPT, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0]));
  return Buffer.concat(parts);
}

// Skip a (possibly compressed) name and return the offset after it.
function skipName(buf, off) {
  for (;;) {
    const len = buf[off];
    if (len === undefined) throw new Error('truncated DNS answer');
    if (len === 0) return off + 1;
    if ((len & 0xc0) === 0xc0) return off + 2;
    off += len + 1;
  }
}

function parseResponse(buf) {
  const flags = buf.readUInt16BE(2);
  const result = {
    rcode: RCODES[flags & 0xf] || `RCODE ${flags & 0xf}`,
    truncated: !!(flags & 0x200),
    // The resolver validated the answer with DNSSEC (only meaningful for resolvers)
    authenticated: !!(flags & 0x20),
    // The answer came with DNSSEC signatures
    signed: false,
    answers: [],
  };
  let off = 12;
  for (let i = buf.readUInt16BE(4); i > 0; i--) off = skipName(buf, off) + 4;
  for (let i = buf.readUInt16BE(6); i > 0; i--) {
    off = skipName(buf, off);
    const type = buf.readUInt16BE(off);
    const length = buf.readUInt16BE(off + 8);
    const data = buf.subarray(off + 10, off + 10 + length);
    off += 10 + length;
    if (type === TYPES.A && length === 4) {
      result.answers.push({type: 'A', value: [...data].join('.')});
    } else if (type === TYPES.TLSA && length > 3) {
      result.answers.push({type: 'TLSA', value: `${data[0]} ${data[1]} ${data[2]} ${data.subarray(3).toString('hex')}`});
    } else if (type === TYPES.RRSIG) {
      result.signed = true;
    }
  }
  return result;
}

async function queryDoh(url, packet) {
  const res = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/dns-message', Accept: 'application/dns-message'},
    body: packet,
    signal: AbortSignal.timeout(TIMEOUT),
  });
  if (!res.ok) throw new Error(`the resolver answered HTTP ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

function queryUdp(host, port, packet) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket(net.isIPv6(host) ? 'udp6' : 'udp4');
    const finish = (err, msg) => {
      clearTimeout(timer);
      socket.close();
      if (err) reject(err);
      else resolve(msg);
    };
    const timer = setTimeout(() => finish(new Error(`no answer from ${host} (timed out)`)), TIMEOUT);
    socket.on('message', msg => {
      if (msg.length >= 2 && msg.readUInt16BE(0) === packet.readUInt16BE(0)) finish(null, msg);
    });
    socket.on('error', err => finish(err));
    socket.send(packet, port, host, err => err && finish(err));
  });
}

// DNS over TCP: each message is prefixed with its length.
function queryTcp(host, port, packet) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({host, port});
    const chunks = [];
    socket.setTimeout(TIMEOUT, () => socket.destroy(new Error(`no answer from ${host} (timed out)`)));
    socket.on('connect', () => {
      const length = Buffer.alloc(2);
      length.writeUInt16BE(packet.length);
      socket.end(Buffer.concat([length, packet]));
    });
    socket.on('data', chunk => chunks.push(chunk));
    socket.on('error', reject);
    socket.on('close', () => {
      const data = Buffer.concat(chunks);
      if (data.length < 2) return reject(new Error(`no answer from ${host}`));
      resolve(data.subarray(2, 2 + data.readUInt16BE(0)));
    });
  });
}

// "host", "host:port", "1.2.3.4", "2001:db8::1" or "[2001:db8::1]:5353"
function parseServer(server) {
  if (net.isIPv6(server)) return {host: server, port: 53};
  const match = /^(?:\[([^\]]+)\]|([^:\s]+))(?::(\d{1,5}))?$/.exec(server);
  if (!match) throw new Error(`invalid DNS server "${server}"`);
  return {host: match[1] || match[2], port: Number(match[3] || 53)};
}

// One question to the server, by whichever transport it takes; returns the raw answer.
async function exchange(server, name, type) {
  if (/^https:\/\//i.test(server)) return queryDoh(server, encodeQuery(name, TYPES[type], {recursive: true}));
  const {host, port} = parseServer(server);
  const packet = encodeQuery(name, TYPES[type], {recursive: false});
  const answer = await queryUdp(host, port, packet);
  return answer[2] & 0x02 ? queryTcp(host, port, packet) : answer;
}

async function query(server, name, type) {
  const response = parseResponse(await exchange(server, name, type));
  response.answers = response.answers.filter(answer => answer.type === type);
  return response;
}

// A (possibly compressed) name, lower-cased, without the trailing dot ('' = root).
function readName(buf, off) {
  const labels = [];
  let end = null;
  for (let hops = 0; hops < 64; hops++) {
    const len = buf[off];
    if (len === undefined) throw new Error('truncated DNS answer');
    if (len === 0) return {name: labels.join('.'), end: end ?? off + 1};
    if ((len & 0xc0) === 0xc0) {
      if (end === null) end = off + 2;
      off = buf.readUInt16BE(off) & 0x3fff;
      continue;
    }
    labels.push(buf.toString('latin1', off + 1, off + 1 + len).toLowerCase());
    off += len + 1;
  }
  throw new Error('DNS name compression loop');
}

// The answer section as raw records: {name, type, ttl, rdata}. The rdata of the
// types used for DANE proofs (DNSKEY, DS, TLSA, RRSIG) holds no compressed names.
async function queryRecords(server, name, type) {
  const buf = await exchange(server, name, type);
  let off = 12;
  for (let i = buf.readUInt16BE(4); i > 0; i--) off = skipName(buf, off) + 4;
  const records = [];
  for (let i = buf.readUInt16BE(6); i > 0; i--) {
    const owner = readName(buf, off);
    off = owner.end;
    const length = buf.readUInt16BE(off + 8);
    records.push({
      name: owner.name,
      type: buf.readUInt16BE(off),
      ttl: buf.readUInt32BE(off + 4),
      rdata: Buffer.from(buf.subarray(off + 10, off + 10 + length)),
    });
    off += 10 + length;
  }
  return {rcode: RCODES[buf[3] & 0xf] || `RCODE ${buf[3] & 0xf}`, records};
}

module.exports = {query, queryRecords, encodeQuery, parseResponse, parseServer, TYPES};
