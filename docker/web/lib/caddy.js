'use strict';

// Castell owns the Caddyfile. The Caddy container runs with --watch, so it reloads
// a second or two after this file changes; an invalid file keeps the old config.
const path = require('path');
const state = require('./state');

// The data folder as mounted in the Caddy container
const CADDY_DATA = process.env.CASTELL_CADDY_DATA || '/castell';

function render(sites) {
  const lines = [
    '# Written by Castell. Edits here are overwritten; change your sites in the Castell app.',
    '{',
    // Certificates are our own (DANE), never from a CA
    '\tauto_https off',
    // Only TCP is forwarded, so don't advertise HTTP/3
    '\tservers {',
    '\t\tprotocols h1 h2',
    '\t}',
  ];
  // For clients that send no name (e.g. "curl https://<ip>"), answer with the first site
  if (sites.length) lines.push(`\tdefault_sni ${sites[0].name}`);
  lines.push('}');

  for (const site of sites) {
    const dir = path.posix.join(CADDY_DATA, 'sites', site.name);
    lines.push(
      '',
      `https://${site.name}, https://*.${site.name} {`,
      // Each certificate gets its own file name, so reissuing one changes this
      // line and Caddy reloads (a comment wouldn't: Caddy ignores comments)
      `\ttls ${dir}/${site.certFile} ${dir}/key.pem`,
      '\tencode gzip',
    );
    if (site.mode === 'proxy') {
      lines.push(`\treverse_proxy ${site.upstream}`);
    } else {
      lines.push(`\troot * ${dir}/site`, '\tfile_server');
    }
    lines.push('}');
  }
  return lines.join('\n') + '\n';
}

function write(sites) {
  state.writeAtomic(path.join(state.DATA_DIR, 'Caddyfile'), render(sites));
}

module.exports = {render, write};
