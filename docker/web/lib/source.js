'use strict';

// Only accept requests that came through Umbrel, so other apps on the same
// Umbrel can't reach Castell (and the site keys) directly and skip the Umbrel login:
// - umbrelOS's app gateway, which reaches this container from the default
//   route's gateway address (Tor remote access goes through it too);
// - older umbrelOS versions run an app_proxy container for this app instead
//   (CASTELL_PROXY_HOST, for example castell-sites_app_proxy_1);
// - loopback, for anything inside this container.
// CASTELL_TRUSTED_IPS adds addresses; CASTELL_ALLOW_ANY_SOURCE=true turns the
// check off, for setups that route traffic some other way.
const dns = require('dns');
const fs = require('fs');

const ALLOW_ANY_SOURCE = process.env.CASTELL_ALLOW_ANY_SOURCE === 'true';
const PROXY_HOST = process.env.CASTELL_PROXY_HOST || '';
const staticTrusted = new Set(['127.0.0.1', '::1']);
for (const ip of (process.env.CASTELL_TRUSTED_IPS || '').split(',')) {
  if (ip.trim()) staticTrusted.add(ip.trim());
}

// The default route's gateway, from the kernel's routing table.
function defaultGateway() {
  try {
    for (const line of fs.readFileSync('/proc/net/route', 'utf8').trim().split('\n').slice(1)) {
      const [, destination, gateway] = line.trim().split(/\s+/);
      if (destination === '00000000' && gateway !== '00000000') {
        // Little-endian hex, e.g. 01001510 -> 16.21.0.1 reversed -> 10.21.0.1
        return gateway.match(/../g).reverse().map(byte => parseInt(byte, 16)).join('.');
      }
    }
  } catch (e) {
    // not Linux, or no routing table: rely on the other sources
  }
  return null;
}

const gatewayIp = defaultGateway();
if (gatewayIp) staticTrusted.add(gatewayIp);

let proxyIps = new Set();
let proxyResolvedAt = 0;
async function refreshProxyIps() {
  if (!PROXY_HOST) return;
  proxyResolvedAt = Date.now();
  try {
    const records = await dns.promises.lookup(PROXY_HOST, {all: true});
    proxyIps = new Set(records.map(record => record.address));
  } catch (e) {
    // Not resolvable: this umbrelOS has no app_proxy container
    proxyIps = new Set();
  }
}

const normalizeIp = ip => String(ip || '').replace(/^::ffff:/, '');
const rejectedLogged = new Set();

async function isTrustedSource(remoteAddress) {
  if (ALLOW_ANY_SOURCE) return true;
  const ip = normalizeIp(remoteAddress);
  if (staticTrusted.has(ip) || proxyIps.has(ip)) return true;
  // The proxy container may have been recreated with a new address.
  if (PROXY_HOST && Date.now() - proxyResolvedAt > 5000) {
    await refreshProxyIps();
    if (proxyIps.has(ip)) return true;
  }
  if (!rejectedLogged.has(ip)) {
    rejectedLogged.add(ip);
    console.warn(`[Castell] Refused a connection from ${ip}: it did not come through Umbrel. ` +
      'Set CASTELL_TRUSTED_IPS or CASTELL_ALLOW_ANY_SOURCE=true if this is expected.');
  }
  return false;
}

function describe() {
  return ALLOW_ANY_SOURCE
    ? 'Source check is off (CASTELL_ALLOW_ANY_SOURCE=true).'
    : `Accepting connections from: ${[...staticTrusted].join(', ')}${PROXY_HOST ? `, ${PROXY_HOST}` : ''}`;
}

module.exports = {isTrustedSource, describe};
