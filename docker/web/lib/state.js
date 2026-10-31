'use strict';

// Llar's data folder (/llar in the container, ~/umbrel/app-data/llar-sites/data on the Umbrel):
//   state.json            settings and the list of sites
//   Caddyfile             generated from state.json, read by the Caddy container
//   sites/<name>/         key.pem, cert-<time>.pem and site/ (the static files)
//   trash/<name>-<time>/  deleted sites, kept so a key is never lost by accident
const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.LLAR_DATA || '/llar';
const STATE_FILE = path.join(DATA_DIR, 'state.json');
const SITES_DIR = path.join(DATA_DIR, 'sites');
const TRASH_DIR = path.join(DATA_DIR, 'trash');

const DEFAULT_SETTINGS = {
  publicIp: '',
  lanIp: '',
  // Where the DNS checks look: a nameserver of your DNS host (authoritative for
  // your zone), or a DNS-over-HTTPS URL. Public Handshake DoH resolvers come
  // and go, so the default asks Yeil's nameserver directly.
  dnsServer: 'a.ns.yeil.org',
};

function load() {
  try {
    const raw = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
    return {settings: {...DEFAULT_SETTINGS, ...raw.settings}, sites: raw.sites || []};
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
    return {settings: {...DEFAULT_SETTINGS}, sites: []};
  }
}

// Write to a temporary file and rename it, so readers (Caddy) never see half a file.
function writeAtomic(file, data, mode = 0o644) {
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, data, {mode});
  fs.renameSync(tmp, file);
}

function save(state) {
  writeAtomic(STATE_FILE, JSON.stringify(state, null, 2) + '\n');
}

// Changes run one at a time: they read state.json, await openssl, then write it back.
let chain = Promise.resolve();
function withLock(fn) {
  const run = chain.then(fn, fn);
  chain = run.catch(() => {});
  return run;
}

const siteDir = name => path.join(SITES_DIR, name);

module.exports = {DATA_DIR, SITES_DIR, TRASH_DIR, load, save, withLock, siteDir, writeAtomic};
