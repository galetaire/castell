'use strict';

// The per-site documents Castell offers for download, and the starter page.

const escapeHtml = text => String(text).replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);

function values(site, tlsa, settings, hostPort) {
  return {
    name: site.name,
    publicIp: settings.publicIp || '<your public IP>',
    lanIp: settings.lanIp || '<Umbrel LAN IP>',
    tlsa: `3 1 1 ${tlsa}`,
    hostPort,
  };
}

function records(site, tlsa, settings, hostPort) {
  const v = values(site, tlsa, settings, hostPort);
  return `DNS records for: ${v.name}
${'='.repeat(17 + v.name.length)}

Publish both at your DNS host (the authoritative, DNSSEC-signed zone, e.g. Yeil).

1) A record: points the name at your home connection
   Name:   @            (i.e. ${v.name})
   Type:   A
   Value:  ${v.publicIp}

2) TLSA record: the DANE pin (public key, 3 1 1)
   Name:   _443._tcp.${v.name}
   Type:   TLSA
   Value:  ${v.tlsa}

Notes
-----
- The TLSA value pins the PUBLIC KEY. Reissuing the certificate from the same
  key keeps this record valid; only a new key needs a new TLSA record.
- Publish the TLSA record and let it propagate BEFORE pointing anyone at the
  site, so the first TLS handshake validates.
- If your public IP changes, update only the A record.
- The name must be delegated to your DNS host in the Handshake root (NS + DS
  records, set once in Bob Wallet).
`;
}

function readme(site, tlsa, settings, hostPort) {
  const v = values(site, tlsa, settings, hostPort);
  const content = site.mode === 'proxy'
    ? `Castell forwards requests for \`${v.name}\` to \`${site.upstream}\` (another app).`
    : 'Static files, uploaded in the Castell app.';
  return `# ${v.name}

Hosted on Umbrel with **Castell**: HTTPS for a Handshake name, secured with **DANE**
(a \`TLSA\` record) instead of a certificate authority. TLS ends on the Umbrel
with this site's own key, so nothing in the middle can re-sign the connection.

\`\`\`
Visitor (DANE-capable Handshake resolver)
   |  ${v.name} -> ${v.publicIp}             (A record)
   |  _443._tcp.${v.name} -> ${v.tlsa.slice(0, 22)}...   (TLSA record)
   v
Router :443  --forward-->  Umbrel ${v.lanIp}:${v.hostPort}  -->  Caddy  -->  site
\`\`\`

Content: ${content}

## Records at your DNS host

| Name | Type | Value |
|---|---|---|
| \`@\` (\`${v.name}\`) | \`A\` | \`${v.publicIp}\` |
| \`_443._tcp.${v.name}\` | \`TLSA\` | \`${v.tlsa}\` |

## Delegation (Bob Wallet, once per name)

The name's records in the Handshake root must point at your DNS host: its \`NS\`
records and the \`DS\` record it gives you.

## Router (once for all Castell sites)

| Field | Value |
|---|---|
| Protocol | TCP |
| External port | \`443\` |
| Internal IP | \`${v.lanIp}\` (reserve it in the router's DHCP settings) |
| Internal port | \`${v.hostPort}\` |

umbrelOS uses port 443 itself, so Caddy listens on ${v.hostPort}; the router maps
the public port 443 onto it. Visitors still connect on 443, so the TLSA name stays
\`_443._tcp.${v.name}\`.

## Key

The private key is in Castell's data folder on the Umbrel
(\`~/umbrel/app-data/castell-sites/data/sites/${v.name}/key.pem\`). Keep a backup
(Castell → the site → Download key). Uninstalling Castell deletes it, and a new key
needs a new TLSA record. To move this site to a new Castell install, add the name
again and choose the backed-up key.

## Checking

- Castell → the site → **Verify** checks the served certificate, both DNS records
  and (when your router allows it) the public address.
- From a phone on mobile data: \`curl -vk https://${v.publicIp}\` should show
  \`server: Caddy\` and a certificate for \`CN=${v.name}\`.
- Open the site in a DANE-capable client (Fingertip, letsdane).
`;
}

function starterPage(name) {
  const safe = escapeHtml(name);
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${safe}</title>
  <style>
    :root { color-scheme: light dark; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center;
      font: 16px/1.6 system-ui, sans-serif; background: #0f1117; color: #e6e8ee; }
    main { max-width: 36rem; padding: 2rem; text-align: center; }
    h1 { font-size: 2rem; margin: 0 0 .5rem; }
    .tag { color: #7dd3fc; font-weight: 600; letter-spacing: .04em; font-size: .85rem; }
  </style>
</head>
<body>
  <main>
    <p class="tag">HANDSHAKE · DANE · HOSTED WITH CASTELL</p>
    <h1>${safe}/ works.</h1>
    <p>This page is served from a home server, over HTTPS validated by a TLSA
      record instead of a certificate authority.</p>
    <p>Replace it by uploading your site in Castell.</p>
  </main>
</body>
</html>
`;
}

module.exports = {records, readme, starterPage};
