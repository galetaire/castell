'use strict';

// Castell: hosts websites for Handshake names on Umbrel, with DANE.
// This server is the app's web UI and API. It owns the data folder (keys,
// certificates, site files) and writes the Caddyfile the Caddy container serves.
const fs = require('fs');
const fsp = fs.promises;
const http = require('http');
const net = require('net');
const path = require('path');
const {domainToASCII} = require('url');

const caddy = require('./lib/caddy');
const certs = require('./lib/certs');
const checks = require('./lib/checks');
const dns = require('./lib/dns');
const docs = require('./lib/docs');
const source = require('./lib/source');
const state = require('./lib/state');
const {UserError} = require('./lib/errors');

const PORT = Number(process.env.PORT || 3000);
// The host port Caddy is published on (docker-compose.yml), for the router instructions
const HOST_PORT = Number(process.env.CASTELL_HOST_PORT || 8443);
// Where this container reaches Caddy, to check the certificate it serves
const CADDY = {host: process.env.CASTELL_CADDY_HOST || 'localhost', port: Number(process.env.CASTELL_CADDY_PORT || 443)};
const IP_SERVICE = process.env.CASTELL_IP_SERVICE || 'https://api.ipify.org';
const PUBLIC_DIR = path.join(__dirname, 'public');
const MAX_JSON = 1024 * 1024;
const MAX_FILE = 512 * 1024 * 1024;

// ---------- validation ----------

const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
const NAME_RE = new RegExp(`^${LABEL}(?:\\.${LABEL})*$`);
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const UPSTREAM_RE = /^(https?:\/\/)?(\[[0-9a-f:]+\]|[a-z0-9_.-]+)(:\d{1,5})?$/i;

// Accepts "mysite", "MySite.", or an emoji/Unicode name (converted to punycode).
function normalizeName(input) {
  const ascii = domainToASCII(String(input || '').trim().toLowerCase().replace(/\.$/, ''));
  if (!ascii || ascii.length > 253 || !NAME_RE.test(ascii)) {
    throw new UserError('That is not a valid Handshake name. Use letters, digits and hyphens, like "mysite".');
  }
  return ascii;
}

function normalizeUpstream(input) {
  const upstream = String(input || '').trim().replace(/\/+$/, '');
  if (!UPSTREAM_RE.test(upstream)) {
    throw new UserError('Enter the app\'s address as host:port, like 192.168.1.27:3000 or http://my-app:8080 (no path).');
  }
  return upstream;
}

function optionalIp(input, label) {
  const ip = String(input || '').trim();
  if (ip && !IPV4_RE.test(ip)) throw new UserError(`${label} must be an IPv4 address, like 203.0.113.7.`);
  return ip;
}

// ---------- sites ----------

const keyFile = name => path.join(state.siteDir(name), 'key.pem');
const certFile = site => path.join(state.siteDir(site.name), site.certFile);
const contentRoot = name => path.join(state.siteDir(name), 'site');
// cert-<time>.pem: a new name for every certificate, see lib/caddy.js
const newCertName = () => `cert-${new Date().toISOString().replace(/\D/g, '').slice(0, 14)}.pem`;

function findSite(current, name) {
  const site = current.sites.find(s => s.name === name);
  if (!site) throw new UserError(`${name} is not in Castell.`);
  return site;
}

function siteView(site) {
  let cert = null;
  try {
    cert = certs.certInfo(certFile(site));
  } catch (e) {
    // shown as "no certificate" in the UI
  }
  return {...site, tlsa: certs.tlsaFromKeyFile(keyFile(site.name)), cert};
}

function saveAndReload(current) {
  current.sites.sort((a, b) => a.name.localeCompare(b.name));
  state.save(current);
  caddy.write(current.sites);
}

async function createSite(body) {
  const name = normalizeName(body.name);
  const mode = body.mode === 'proxy' ? 'proxy' : 'static';
  const upstream = mode === 'proxy' ? normalizeUpstream(body.upstream) : '';
  const importedKey = body.keyPem ? certs.normalizeKey(body.keyPem) : null;

  return state.withLock(async () => {
    const current = state.load();
    if (current.sites.some(s => s.name === name)) throw new UserError(`${name} is already in Castell.`);
    const dir = state.siteDir(name);
    if (fs.existsSync(dir)) throw new UserError(`Castell's data folder already has files for ${name} (sites/${name}). Move them away first.`);

    const now = new Date().toISOString();
    const site = {name, mode, upstream, keyImported: !!importedKey, createdAt: now, certFile: newCertName()};
    await fsp.mkdir(contentRoot(name), {recursive: true});
    try {
      if (importedKey) state.writeAtomic(keyFile(name), importedKey, 0o600);
      else await certs.generateKey(keyFile(name));
      await certs.issueCert(name, keyFile(name), certFile(site));
      if (mode === 'static') await fsp.writeFile(path.join(contentRoot(name), 'index.html'), docs.starterPage(name));
    } catch (e) {
      await fsp.rm(dir, {recursive: true, force: true});
      throw e;
    }

    current.sites.push(site);
    saveAndReload(current);
    return siteView(site);
  });
}

function updateSite(name, body) {
  return state.withLock(async () => {
    const current = state.load();
    const site = findSite(current, name);
    site.mode = body.mode === 'proxy' ? 'proxy' : 'static';
    site.upstream = site.mode === 'proxy' ? normalizeUpstream(body.upstream) : '';
    saveAndReload(current);
    return siteView(site);
  });
}

// Moves the site to trash/ rather than deleting it: its key may still be in a TLSA record.
function deleteSite(name) {
  return state.withLock(async () => {
    const current = state.load();
    findSite(current, name);
    await fsp.mkdir(state.TRASH_DIR, {recursive: true});
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    await fsp.rename(state.siteDir(name), path.join(state.TRASH_DIR, `${name}-${stamp}`));
    current.sites = current.sites.filter(s => s.name !== name);
    saveAndReload(current);
  });
}

function renewCert(name) {
  return state.withLock(async () => {
    const current = state.load();
    const site = findSite(current, name);
    const oldCert = certFile(site);
    const certName = newCertName();
    // Two reissues in the same second would reuse the name and Caddy wouldn't reload
    if (certName === site.certFile) throw new UserError('A certificate was just issued; wait a moment.');
    await certs.issueCert(name, keyFile(name), path.join(state.siteDir(name), certName));
    site.certFile = certName;
    saveAndReload(current);
    // Caddy holds the old certificate in memory until it reloads, so the file can go now
    await fsp.rm(oldCert, {force: true});
    return siteView(site);
  });
}

// ---------- site files ----------

function contentPath(name, relative) {
  const parts = String(relative || '').replace(/\\/g, '/').split('/').filter(Boolean);
  if (!parts.length || parts.some(p => p === '.' || p === '..' || p.includes('\0'))) {
    throw new UserError('Invalid file path.');
  }
  const root = contentRoot(name);
  const full = path.join(root, ...parts);
  if (!full.startsWith(root + path.sep)) throw new UserError('Invalid file path.');
  return full;
}

async function listFiles(root, base = '', out = []) {
  for (const entry of await fsp.readdir(path.join(root, base), {withFileTypes: true})) {
    if (out.length >= 5000) break;
    const relative = base ? `${base}/${entry.name}` : entry.name;
    if (entry.isDirectory()) await listFiles(root, relative, out);
    else if (entry.isFile()) out.push({path: relative, size: (await fsp.stat(path.join(root, relative))).size});
  }
  return out;
}

// Streams the request body to disk (through a temporary file) with a size limit.
async function saveUpload(req, dest) {
  await fsp.mkdir(path.dirname(dest), {recursive: true});
  const tmp = `${dest}.castell-upload`;
  try {
    await new Promise((resolve, reject) => {
      let size = 0;
      const out = fs.createWriteStream(tmp);
      req.on('data', chunk => {
        size += chunk.length;
        if (size > MAX_FILE) {
          req.unpipe(out);
          out.destroy();
          reject(new UserError('That file is larger than 512 MB.'));
        }
      });
      req.on('error', reject);
      out.on('error', reject);
      out.on('finish', resolve);
      req.pipe(out);
    });
    await fsp.rename(tmp, dest);
  } catch (e) {
    await fsp.rm(tmp, {force: true});
    throw e;
  }
}

// ---------- misc ----------

function caddyListening() {
  return new Promise(resolve => {
    const socket = net.connect(CADDY);
    const done = up => {
      socket.destroy();
      resolve(up);
    };
    socket.setTimeout(1500, () => done(false));
    socket.once('connect', () => done(true));
    socket.once('error', () => done(false));
  });
}

async function detectPublicIp() {
  let text;
  try {
    const res = await fetch(IP_SERVICE, {signal: AbortSignal.timeout(6000)});
    text = (await res.text()).trim();
  } catch (e) {
    throw new UserError(`Could not reach ${IP_SERVICE} to detect your public IP. Enter it by hand.`);
  }
  if (!IPV4_RE.test(text)) throw new UserError(`${IP_SERVICE} did not return an IPv4 address. Enter it by hand.`);
  return text;
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_JSON) {
        reject(new UserError('Request is too large.'));
        req.destroy();
      } else {
        chunks.push(chunk);
      }
    });
    req.on('end', () => {
      try {
        resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {});
      } catch (e) {
        reject(new UserError('Invalid JSON.'));
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, body) {
  res.writeHead(status, {'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store'});
  res.end(JSON.stringify(body));
}

function sendDownload(res, filename, type, data) {
  res.writeHead(200, {
    'Content-Type': type,
    'Content-Disposition': `attachment; filename="${filename}"`,
    'Cache-Control': 'no-store',
  });
  res.end(data);
}

const STATIC_TYPES = {'.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2'};

async function serveStatic(res, pathname) {
  const file = path.join(PUBLIC_DIR, pathname === '/' ? 'index.html' : pathname);
  if (!file.startsWith(PUBLIC_DIR + path.sep)) return sendJson(res, 404, {error: 'Not found'});
  try {
    const data = await fsp.readFile(file);
    res.writeHead(200, {'Content-Type': STATIC_TYPES[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache'});
    res.end(data);
  } catch (e) {
    sendJson(res, 404, {error: 'Not found'});
  }
}

// ---------- routes ----------

const routes = [];
const route = (method, pattern, handler) => routes.push({method, pattern, handler});

route('GET', /^\/api\/state$/, async () => {
  const current = state.load();
  return {
    settings: current.settings,
    hostPort: HOST_PORT,
    caddyListening: current.sites.length ? await caddyListening() : null,
    sites: current.sites.map(siteView),
  };
});

route('PUT', /^\/api\/settings$/, async ({body}) => {
  const dnsServer = String(body.dnsServer || '').trim();
  if (!/^https:\/\/\S+$/i.test(dnsServer)) {
    try {
      dns.parseServer(dnsServer);
    } catch (e) {
      throw new UserError('The DNS server must be a nameserver (like a.ns.yeil.org) or a DNS-over-HTTPS URL (https://...).');
    }
  }
  return state.withLock(async () => {
    const current = state.load();
    current.settings = {
      publicIp: optionalIp(body.publicIp, 'The public IP'),
      lanIp: optionalIp(body.lanIp, 'The Umbrel LAN IP'),
      dnsServer,
    };
    state.save(current);
    return current.settings;
  });
});

route('GET', /^\/api\/public-ip$/, async () => ({ip: await detectPublicIp()}));

route('POST', /^\/api\/sites$/, async ({body}) => createSite(body));
route('PATCH', /^\/api\/sites\/([^/]+)$/, async ({params, body}) => updateSite(params[0], body));
route('DELETE', /^\/api\/sites\/([^/]+)$/, async ({params}) => {
  await deleteSite(params[0]);
  return {ok: true};
});
route('POST', /^\/api\/sites\/([^/]+)\/renew$/, async ({params}) => renewCert(params[0]));

route('POST', /^\/api\/sites\/([^/]+)\/verify$/, async ({params}) => {
  const current = state.load();
  const site = findSite(current, params[0]);
  return {checks: await checks.run(site, certs.tlsaFromKeyFile(keyFile(site.name)), current.settings, CADDY)};
});

route('GET', /^\/api\/sites\/([^/]+)\/files$/, async ({params}) => {
  findSite(state.load(), params[0]);
  return {files: await listFiles(contentRoot(params[0]))};
});

route('PUT', /^\/api\/sites\/([^/]+)\/files$/, async ({params, url, req}) => {
  findSite(state.load(), params[0]);
  await saveUpload(req, contentPath(params[0], url.searchParams.get('path')));
  return {ok: true};
});

// Empties the site folder, before uploading a new version of the site
route('DELETE', /^\/api\/sites\/([^/]+)\/files$/, async ({params}) => {
  findSite(state.load(), params[0]);
  const root = contentRoot(params[0]);
  await fsp.rm(root, {recursive: true, force: true});
  await fsp.mkdir(root, {recursive: true});
  return {ok: true};
});

route('GET', /^\/api\/sites\/([^/]+)\/download\/(key|cert|records|readme)$/, async ({params, res}) => {
  const current = state.load();
  const site = findSite(current, params[0]);
  const tlsa = certs.tlsaFromKeyFile(keyFile(site.name));
  const downloads = {
    key: () => [`${site.name}-key.pem`, 'application/x-pem-file', fs.readFileSync(keyFile(site.name))],
    cert: () => [`${site.name}-cert.pem`, 'application/x-pem-file', fs.readFileSync(certFile(site))],
    records: () => [`${site.name}-dns-records.txt`, 'text/plain; charset=utf-8', docs.records(site, tlsa, current.settings, HOST_PORT)],
    readme: () => [`${site.name}-README.md`, 'text/markdown; charset=utf-8', docs.readme(site, tlsa, current.settings, HOST_PORT)],
  };
  sendDownload(res, ...downloads[params[1]]());
});

// ---------- server ----------

const server = http.createServer(async (req, res) => {
  if (!(await source.isTrustedSource(req.socket.remoteAddress))) return sendJson(res, 403, {error: 'Forbidden'});

  const url = new URL(req.url, 'http://localhost');
  let pathname;
  try {
    pathname = decodeURIComponent(url.pathname);
  } catch (e) {
    return sendJson(res, 400, {error: 'Bad URL'});
  }

  if (!pathname.startsWith('/api/')) {
    if (req.method !== 'GET' && req.method !== 'HEAD') return sendJson(res, 405, {error: 'Method not allowed'});
    return serveStatic(res, pathname);
  }

  // Changes need a header a cross-site form or image can't send, so another
  // website open in the same browser can't act on Castell through the Umbrel login.
  if (req.method !== 'GET' && req.headers['x-castell'] !== '1') return sendJson(res, 403, {error: 'Missing X-Castell header'});

  for (const {method, pattern, handler} of routes) {
    const match = method === req.method && pattern.exec(pathname);
    if (!match) continue;
    try {
      const params = match.slice(1);
      const streaming = method === 'PUT' && pathname.endsWith('/files');
      const body = method === 'GET' || method === 'DELETE' || streaming ? {} : await readJson(req);
      const result = await handler({req, res, url, params, body});
      if (!res.headersSent) sendJson(res, 200, result);
    } catch (e) {
      if (e instanceof UserError) return sendJson(res, 400, {error: e.message});
      console.error(`[Castell] ${req.method} ${pathname}:`, e);
      return sendJson(res, 500, {error: e.message});
    }
    return;
  }
  sendJson(res, 404, {error: 'Not found'});
});

fs.mkdirSync(state.SITES_DIR, {recursive: true});
// Always rewrite the Caddyfile on start, so a new Castell version's config takes effect
caddy.write(state.load().sites);

server.listen(PORT, () => {
  console.log(`[Castell] Listening on port ${PORT}. Data folder: ${state.DATA_DIR}`);
  console.log(`[Castell] ${source.describe()}`);
});
