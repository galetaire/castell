'use strict';

// Minimal DNS client for A and TLSA lookups. The server is either:
// - a nameserver, "host" or "host:port" (plain DNS over UDP, TCP if truncated).
//   Usually your DNS host's own nameserver (e.g. a.ns.yeil.org): it answers
//   authoritatively for your zone, so it shows exactly what you published.
// - a DNS-over-HTTPS URL, "https://..." (RFC 8484), e.g. a Handshake resolver.
const dgram = require('dgram');
const net = require('net');

const TYPES = {A: 1, TLSA: 52, RRSIG: 46, OPT: 41};
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

async function query(server, name, type) {
  let response;
  if (/^https:\/\//i.test(server)) {
    response = parseResponse(await queryDoh(server, encodeQuery(name, TYPES[type], {recursive: true})));
  } else {
    const {host, port} = parseServer(server);
    const packet = encodeQuery(name, TYPES[type], {recursive: false});
    response = parseResponse(await queryUdp(host, port, packet));
    if (response.truncated) response = parseResponse(await queryTcp(host, port, packet));
  }
  response.answers = response.answers.filter(answer => answer.type === type);
  return response;
}

module.exports = {query, encodeQuery, parseResponse, parseServer};
