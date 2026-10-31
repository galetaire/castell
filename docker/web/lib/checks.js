'use strict';

const https = require('https');
const certs = require('./certs');
const dns = require('./dns');

// Node reports a refused connection to "localhost" as an AggregateError with no message.
const errorText = e => e.code || e.message || (e.errors && e.errors[0] && e.errors[0].code) || String(e);

// GET / over TLS with the site's name, and report the status and the served key's TLSA value.
function fetchServed(host, port, servername) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      host, port, servername, path: '/', method: 'GET',
      headers: {Host: servername},
      // The certificate is self-signed; what matters is whether its key matches the TLSA record
      rejectUnauthorized: false,
      agent: false,
      timeout: 6000,
    }, res => {
      const cert = res.socket.getPeerX509Certificate();
      res.resume();
      resolve({
        status: res.statusCode,
        tlsa: cert ? certs.tlsaFromCert(cert) : null,
        issuer: cert ? cert.issuer.split('\n').join(', ') : 'none',
      });
    });
    req.on('timeout', () => req.destroy(new Error('timed out')));
    req.on('error', reject);
    req.end();
  });
}

function describeStatus(site, status) {
  if (site.mode === 'proxy' && status >= 502 && status <= 504) {
    return {status: 'warn', detail: `the app at ${site.upstream} is not answering (HTTP ${status})`};
  }
  if (site.mode === 'static' && status === 404) {
    return {status: 'warn', detail: 'no index.html at the top of the site folder (HTTP 404)'};
  }
  return null;
}

async function checkCaddy(site, tlsa, caddy) {
  const check = {id: 'caddy', label: 'Caddy serves the site with your key'};
  try {
    const served = await fetchServed(caddy.host, caddy.port, site.name);
    if (served.tlsa !== tlsa) {
      return {...check, status: 'fail', detail: `Caddy is serving a different certificate (issued by ${served.issuer}). It reloads a few seconds after a change; try again shortly.`};
    }
    return {...check, status: 'ok', detail: `HTTP ${served.status}, certificate matches the TLSA value`, ...describeStatus(site, served.status)};
  } catch (e) {
    return {...check, status: 'fail', detail: `could not reach Caddy (${errorText(e)}). Check that the app's caddy container is running.`};
  }
}

// Looks up one record and turns the answer into a check result. matches(values) decides success.
async function checkRecord(check, server, name, type, matches, describeMismatch) {
  let result;
  try {
    result = await dns.query(server, name, type);
  } catch (e) {
    return {...check, status: 'warn', detail: `could not ask ${server} (${errorText(e)})`};
  }
  const values = result.answers.map(answer => answer.value);
  if (result.rcode === 'REFUSED') {
    return {...check, status: 'fail', detail: `${server} does not host this zone. Create the zone at your DNS host, or change the DNS server in Llar's settings.`};
  }
  if (!values.length) {
    return {...check, status: 'fail', detail: `no ${type} record published (${result.rcode}). Add it at your DNS host.`};
  }
  if (!matches(values)) return {...check, status: 'fail', detail: describeMismatch(values)};
  if (result.authenticated) return {...check, status: 'ok', detail: 'published, validated with DNSSEC'};
  if (result.signed) return {...check, status: 'ok', detail: 'published and DNSSEC-signed'};
  return {...check, status: 'warn', detail: 'published, but without DNSSEC signatures. DANE needs a signed zone; check the DS record in Bob Wallet and DNSSEC at your DNS host.'};
}

function checkA(site, settings) {
  const check = {id: 'dns-a', label: `A record for ${site.name}`};
  if (!settings.publicIp) return {...check, status: 'warn', detail: 'set your public IP in Llar first'};
  return checkRecord(check, settings.dnsServer, site.name, 'A',
    values => values.includes(settings.publicIp),
    values => `points to ${values.join(', ')}, not your public IP ${settings.publicIp}`);
}

function checkTlsa(site, tlsa, settings) {
  const name = `_443._tcp.${site.name}`;
  const expected = `3 1 1 ${tlsa}`;
  return checkRecord({id: 'dns-tlsa', label: `TLSA record for ${name}`}, settings.dnsServer, name, 'TLSA',
    values => values.includes(expected),
    values => `found ${values.join(', ')}, but this site's key needs ${expected}`);
}

// Through the public IP, as a visitor would arrive. Many routers can't loop a
// connection from inside the network back in ("NAT loopback"), so a failure here
// isn't conclusive; a phone on mobile data is the real test.
async function checkPublic(site, tlsa, settings) {
  const check = {id: 'public', label: 'Reachable on your public IP, port 443'};
  if (!settings.publicIp) return {...check, status: 'warn', detail: 'set your public IP in Llar first'};
  try {
    const served = await fetchServed(settings.publicIp, 443, site.name);
    if (served.tlsa !== tlsa) {
      return {
        ...check, status: 'fail',
        detail: `${settings.publicIp}:443 answers with a different certificate (issued by ${served.issuer}). ` +
          'Check that the router forwards to this Umbrel\'s port 8443, and that no proxy sits in between.',
      };
    }
    return {...check, status: 'ok', detail: `${settings.publicIp}:443 answers with your certificate (HTTP ${served.status})`};
  } catch (e) {
    return {
      ...check, status: 'warn',
      detail: `no answer from inside your network (${errorText(e)}). Your router may not support NAT loopback, so test from a phone on mobile data.`,
    };
  }
}

async function run(site, tlsa, settings, caddy) {
  return Promise.all([
    checkCaddy(site, tlsa, caddy),
    checkA(site, settings),
    checkTlsa(site, tlsa, settings),
    checkPublic(site, tlsa, settings),
  ]);
}

module.exports = {run};
