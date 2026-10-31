'use strict';

// Castell's web UI: plain JavaScript, rendered from the /api/state snapshot.
const app = document.getElementById('app');
let data = null;
const verifyResults = {};

// ---------- helpers ----------

const esc = text => String(text ?? '').replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

async function api(method, url, body, rawBody = false) {
  const options = {method, headers: {'X-Castell': '1'}};
  if (body !== undefined) {
    if (rawBody) {
      options.body = body;
    } else {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body);
    }
  }
  const res = await fetch(url, options);
  const result = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(result.error || `Request failed (HTTP ${res.status})`);
  return result;
}

let toastTimer;
function toast(message, isError = false) {
  const el = document.getElementById('toast');
  el.textContent = message;
  el.className = isError ? 'toast error' : 'toast';
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.hidden = true), isError ? 7000 : 3500);
}

// Runs an async action from a button, disabling it meanwhile and reporting errors.
async function busy(button, action) {
  const label = button.textContent;
  button.disabled = true;
  try {
    await action();
  } catch (e) {
    toast(e.message, true);
  } finally {
    button.disabled = false;
    if (button.isConnected) button.textContent = label;
  }
}

// The Umbrel UI is usually plain http, where navigator.clipboard is unavailable.
async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const area = document.createElement('textarea');
  area.value = text;
  area.style.position = 'fixed';
  area.style.opacity = '0';
  document.body.appendChild(area);
  area.select();
  document.execCommand('copy');
  area.remove();
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

const formatDate = iso => new Date(iso).toLocaleDateString(undefined, {year: 'numeric', month: 'short', day: 'numeric'});
const siteUrl = name => `api/sites/${encodeURIComponent(name)}`;
const lanIp = () => data.settings.lanIp || '<Umbrel LAN IP>';

// ---------- data ----------

async function refresh() {
  data = await api('GET', 'api/state');
  const pill = document.getElementById('caddy-status');
  pill.hidden = false;
  if (data.caddyListening === null) {
    pill.className = 'pill idle';
    pill.textContent = 'No sites yet';
  } else if (data.caddyListening) {
    pill.className = 'pill ok';
    pill.textContent = `Serving ${data.sites.length} site${data.sites.length === 1 ? '' : 's'}`;
  } else {
    pill.className = 'pill fail';
    pill.textContent = 'Web server not reachable';
  }
}

async function route() {
  const match = /^#\/site\/(.+)$/.exec(location.hash);
  const name = match && decodeURIComponent(match[1]);
  // A site added elsewhere (another tab) since this page loaded
  if (name && !data.sites.some(s => s.name === name)) await refresh().catch(() => {});
  const site = name && data.sites.find(s => s.name === name);
  if (site) renderSite(site);
  else renderHome();
  window.scrollTo(0, 0);
}

// ---------- home ----------

function routerTable() {
  return `
    <div class="table-wrap"><table>
      <tr><th>Protocol</th><th>External port</th><th>Internal IP</th><th>Internal port</th></tr>
      <tr><td>TCP</td><td class="mono">443</td><td class="mono">${esc(lanIp())}</td><td class="mono">${data.hostPort}</td></tr>
    </table></div>`;
}

function renderHome() {
  const {settings, sites} = data;
  // The browser reached Castell through the Umbrel's LAN address: a good guess for the router rule
  const suggestedLan = !settings.lanIp && IPV4_RE.test(location.hostname) ? location.hostname : '';

  app.innerHTML = `
    <section class="card">
      <h2>Your sites</h2>
      ${sites.length ? `<ul class="sites">${sites.map(site => `
        <li><a href="#/site/${encodeURIComponent(site.name)}">
          <span><span class="site-name">${esc(site.name)}/</span>
            <span class="badge">${site.mode === 'proxy' ? `app → ${esc(site.upstream)}` : 'static'}</span></span>
          <span class="muted small">Open →</span>
        </a></li>`).join('')}</ul>`
        : '<p class="muted">No sites yet. Add your first Handshake name below.</p>'}
    </section>

    <section class="card">
      <h2>Add a site</h2>
      <form id="add-form">
        <label for="add-name">Handshake name
          <span class="hint">The name you own, like <code>mysite</code>. Subdomains (<code>www.mysite</code>) are served automatically.</span>
        </label>
        <input type="text" id="add-name" required autocomplete="off" spellcheck="false" placeholder="mysite">

        <label>What it serves</label>
        <div class="segmented" role="group">
          <button type="button" data-mode="static" aria-pressed="true">Static website</button>
          <button type="button" data-mode="proxy" aria-pressed="false">Another app</button>
        </div>
        <div id="add-upstream" hidden>
          <label for="add-upstream-input">App address
            <span class="hint">Where the app listens, as host:port, e.g. <code>${esc(settings.lanIp || '192.168.1.27')}:3000</code>.</span>
          </label>
          <input type="text" id="add-upstream-input" autocomplete="off" spellcheck="false" placeholder="192.168.1.27:3000">
        </div>

        <label for="add-key">Existing key <span class="muted">(optional)</span>
          <span class="hint">Moving a site that already has a TLSA record? Choose its <code>key.pem</code> to keep that record. Leave empty to create a new key.</span>
        </label>
        <input type="file" id="add-key" accept=".pem,.key,text/plain">

        <div class="actions"><button class="primary" type="submit">Add site</button></div>
      </form>
    </section>

    <section class="card">
      <h2>Your connection</h2>
      <form id="settings-form">
        <div class="grid-2">
          <div>
            <label for="set-public">Public IP
              <span class="hint">Your home's internet address. Goes in each site's A record.</span>
            </label>
            <div class="row">
              <input type="text" id="set-public" value="${esc(settings.publicIp)}" placeholder="203.0.113.7" spellcheck="false">
              <button type="button" id="detect-ip">Detect</button>
            </div>
          </div>
          <div>
            <label for="set-lan">Umbrel LAN IP
              <span class="hint">This Umbrel on your home network${suggestedLan ? ' (filled in from your browser\'s address)' : ''}. Reserve it in your router's DHCP settings.</span>
            </label>
            <input type="text" id="set-lan" value="${esc(settings.lanIp || suggestedLan)}" placeholder="192.168.1.27" spellcheck="false">
          </div>
        </div>
        <label for="set-dns">DNS server to check against
          <span class="hint">Your DNS host's nameserver, which shows exactly what you published (Yeil: <code>a.ns.yeil.org</code>). A Handshake DNS-over-HTTPS URL also works.</span>
        </label>
        <input type="text" id="set-dns" value="${esc(settings.dnsServer)}" spellcheck="false">
        <div class="actions"><button class="primary" type="submit">Save</button></div>
      </form>
    </section>

    <section class="card">
      <h2>Router: one rule for all sites</h2>
      <p>Add this port forward in your router (often under <em>Port forwarding</em>, <em>Virtual server</em> or <em>NAT</em>):</p>
      ${routerTable()}
      <p class="muted small">umbrelOS uses port 443 itself, so Castell listens on ${data.hostPort}. Visitors still connect on 443; the router maps it.
        Leave any "remote host" field empty, and enable the rule after saving.</p>
    </section>`;

  // Add site
  let mode = 'static';
  for (const button of app.querySelectorAll('.segmented button')) {
    button.onclick = () => {
      mode = button.dataset.mode;
      for (const other of app.querySelectorAll('.segmented button')) other.setAttribute('aria-pressed', String(other === button));
      document.getElementById('add-upstream').hidden = mode !== 'proxy';
    };
  }
  document.getElementById('add-form').onsubmit = event => {
    event.preventDefault();
    busy(event.submitter, async () => {
      event.submitter.textContent = 'Creating key and certificate…';
      const keyFile = document.getElementById('add-key').files[0];
      const site = await api('POST', 'api/sites', {
        name: document.getElementById('add-name').value,
        mode,
        upstream: document.getElementById('add-upstream-input').value,
        keyPem: keyFile ? await keyFile.text() : undefined,
      });
      await refresh();
      toast(`${site.name}/ added. Next: publish its records.`);
      location.hash = `#/site/${encodeURIComponent(site.name)}`;
    });
  };

  // Settings
  document.getElementById('detect-ip').onclick = event => busy(event.currentTarget, async () => {
    const {ip} = await api('GET', 'api/public-ip');
    document.getElementById('set-public').value = ip;
    toast(`Detected ${ip}. Save to keep it.`);
  });
  document.getElementById('settings-form').onsubmit = event => {
    event.preventDefault();
    busy(event.submitter, async () => {
      await api('PUT', 'api/settings', {
        publicIp: document.getElementById('set-public').value,
        lanIp: document.getElementById('set-lan').value,
        dnsServer: document.getElementById('set-dns').value,
      });
      await refresh();
      renderHome();
      toast('Saved.');
    });
  };
}

// ---------- site ----------

function recordRow(name, type, value) {
  return `<tr>
    <td class="mono">${esc(name)}</td><td class="mono">${type}</td>
    <td class="mono value">${esc(value)}</td>
    <td><button type="button" class="small" data-copy="${esc(value)}">Copy</button></td>
  </tr>`;
}

function checksList(checks) {
  const icons = {ok: '✓', warn: '!', fail: '✗'};
  return `<ul class="checks">${checks.map(check => `
    <li class="${check.status}"><span class="icon">${icons[check.status]}</span>
      <span><strong>${esc(check.label)}</strong><br><span class="small">${esc(check.detail)}</span></span></li>`).join('')}</ul>`;
}

function contentSection(site) {
  if (site.mode === 'proxy') {
    return `
      <p>Requests for <strong>${esc(site.name)}/</strong> go to the app at:</p>
      <div class="row">
        <input type="text" id="upstream" value="${esc(site.upstream)}" spellcheck="false">
        <button type="button" id="save-upstream">Save</button>
      </div>
      <p class="muted small">Use the address the Umbrel can reach, e.g. <code>${esc(data.settings.lanIp || '192.168.1.27')}:3000</code> for an app published on that port.
        <button type="button" class="small" id="to-static">Serve static files instead</button></p>`;
  }
  return `
    <p>Upload your website's files. The folder's <code>index.html</code> becomes the home page.</p>
    <div class="actions" style="margin-top:.5rem">
      <label class="button primary" for="upload-folder" style="margin:0">Upload a folder</label>
      <input type="file" id="upload-folder" webkitdirectory multiple hidden>
      <label class="button" for="upload-files" style="margin:0">Upload files</label>
      <input type="file" id="upload-files" multiple hidden>
    </div>
    <label class="hint" style="margin-top:.6rem"><input type="checkbox" id="replace" checked> Replace the current site (removes files not in the upload)</label>
    <p id="upload-progress" class="small muted"></p>
    <div id="file-list" class="small muted">Loading files…</div>
    <p class="muted small" style="margin-top:.8rem">Dynamic site? <button type="button" class="small" id="to-proxy">Point this name at another app</button></p>`;
}

function renderSite(site) {
  const {settings} = data;
  const name = site.name;
  const publicIp = settings.publicIp || '<your public IP>';

  app.innerHTML = `
    <a class="back" href="#/">← All sites</a>
    <div class="title-row">
      <h1>${esc(name)}/</h1>
      <span class="badge">${site.mode === 'proxy' ? 'app' : 'static'}</span>
      ${site.keyImported ? '<span class="badge">imported key</span>' : ''}
    </div>

    <div class="callout warn">
      <strong>Back up this site's key</strong>
      Your TLSA record is tied to this key. If you uninstall Castell or lose the Umbrel, the key is gone and you'd need a new TLSA record.
      <div class="actions" style="margin-top:.5rem"><a class="button small" href="${siteUrl(name)}/download/key" download>Download key.pem</a></div>
    </div>

    <section class="card step">
      <span class="step-num">1</span>
      <div class="step-body">
        <h2>Publish these records at your DNS host</h2>
        ${settings.publicIp ? '' : '<p class="callout warn">Set your public IP on the <a href="#/">main page</a> first, so the A record is complete.</p>'}
        <div class="table-wrap"><table>
          <tr><th>Name</th><th>Type</th><th>Value</th><th></th></tr>
          ${recordRow(`@  (${name})`, 'A', publicIp)}
          ${recordRow(`_443._tcp.${name}`, 'TLSA', `3 1 1 ${site.tlsa}`)}
        </table></div>
        <p class="muted small">At Yeil, the TLSA name may be entered as <code>_443._tcp</code> inside the <code>${esc(name)}</code> zone. Publish the TLSA record before sharing the site.</p>
      </div>
    </section>

    <section class="card step">
      <span class="step-num">2</span>
      <div class="step-body">
        <h2>Delegate the name to your DNS host</h2>
        <p>Once per name, in <strong>Bob Wallet → Domain Manager → ${esc(name)}</strong>, add the two <code>NS</code> records and the <code>DS</code> record your DNS host gives you (Yeil: <code>a.ns.yeil.org.</code> and <code>b.ns.yeil.org.</code>). Skip this if you've done it already.</p>
      </div>
    </section>

    <section class="card step">
      <span class="step-num">3</span>
      <div class="step-body">
        <h2>Router</h2>
        <p>The same rule serves every Castell site. If it's set up already, nothing to do:</p>
        ${routerTable()}
      </div>
    </section>

    <section class="card step">
      <span class="step-num">4</span>
      <div class="step-body">
        <h2>Content</h2>
        ${contentSection(site)}
      </div>
    </section>

    <section class="card step">
      <span class="step-num">5</span>
      <div class="step-body">
        <h2>Verify</h2>
        <p>Checks the certificate being served, both DNS records, and your public address. DNS changes can take a while to show up.</p>
        <div class="actions" style="margin-top:.5rem"><button type="button" class="primary" id="verify">Run checks</button></div>
        <div id="verify-results">${verifyResults[name] ? checksList(verifyResults[name]) : ''}</div>
        <p class="muted small" style="margin-top:.8rem">From outside, a phone on mobile data should get your page with
          <code>curl -vk https://${esc(publicIp)}</code>. Visitors open <strong>${esc(name)}/</strong> with a DANE-capable Handshake resolver (Fingertip, letsdane).</p>
      </div>
    </section>

    <section class="card">
      <h2>More</h2>
      <p class="small">Certificate valid until <strong>${site.cert ? formatDate(site.cert.validTo) : 'unknown'}</strong>.
        Reissuing it keeps the same key, so your TLSA record stays valid.</p>
      <div class="actions">
        <a class="button small" href="${siteUrl(name)}/download/records" download>dns-records.txt</a>
        <a class="button small" href="${siteUrl(name)}/download/readme" download>README.md</a>
        <a class="button small" href="${siteUrl(name)}/download/cert" download>cert.pem</a>
        <button type="button" class="small" id="renew">Reissue certificate</button>
        <button type="button" class="small danger" id="remove">Remove site</button>
      </div>
    </section>`;

  for (const button of app.querySelectorAll('[data-copy]')) {
    button.onclick = async () => {
      await copyText(button.dataset.copy);
      button.textContent = 'Copied';
      setTimeout(() => (button.textContent = 'Copy'), 1500);
    };
  }

  const setMode = (button, modeBody, message) => busy(button, async () => {
    await api('PATCH', siteUrl(name), modeBody);
    await refresh();
    route();
    toast(message);
  });

  if (site.mode === 'proxy') {
    document.getElementById('save-upstream').onclick = event => setMode(event.currentTarget,
      {mode: 'proxy', upstream: document.getElementById('upstream').value}, 'Saved. Caddy reloads in a few seconds.');
    document.getElementById('to-static').onclick = event => setMode(event.currentTarget, {mode: 'static'}, 'Now serving the static files.');
  } else {
    loadFiles(name);
    document.getElementById('upload-folder').onchange = event => upload(name, event.target, true);
    document.getElementById('upload-files').onchange = event => upload(name, event.target, false);
    document.getElementById('to-proxy').onclick = event => {
      const button = event.currentTarget;
      const upstream = prompt(`Address of the app (host:port), e.g. ${data.settings.lanIp || '192.168.1.27'}:3000`);
      if (upstream) setMode(button, {mode: 'proxy', upstream}, 'Now forwarding to the app.');
    };
  }

  document.getElementById('verify').onclick = event => busy(event.currentTarget, async () => {
    event.currentTarget.textContent = 'Checking…';
    const {checks} = await api('POST', `${siteUrl(name)}/verify`);
    verifyResults[name] = checks;
    document.getElementById('verify-results').innerHTML = checksList(checks);
  });

  document.getElementById('renew').onclick = event => busy(event.currentTarget, async () => {
    await api('POST', `${siteUrl(name)}/renew`);
    await refresh();
    route();
    toast('New certificate issued with the same key. Your TLSA record is unchanged.');
  });

  document.getElementById('remove').onclick = event => {
    if (!confirm(`Remove ${name}/ from Castell?\n\nIt stops being served. Its key and files are moved to the "trash" folder in Castell's data on the Umbrel, not deleted.`)) return;
    busy(event.currentTarget, async () => {
      await api('DELETE', siteUrl(name));
      await refresh();
      location.hash = '#/';
      toast(`${name}/ removed.`);
    });
  };
}

async function loadFiles(name) {
  const el = document.getElementById('file-list');
  try {
    const {files} = await api('GET', `${siteUrl(name)}/files`);
    if (!el.isConnected) return;
    const total = files.reduce((sum, file) => sum + file.size, 0);
    const hasIndex = files.some(file => file.path === 'index.html');
    el.innerHTML = files.length
      ? `<details><summary>${files.length} file${files.length === 1 ? '' : 's'}, ${formatSize(total)}${hasIndex ? '' : ' (no index.html at the top!)'}</summary>
          <ul class="files">${files.map(file => `<li><span class="mono">${esc(file.path)}</span> <span class="muted">${formatSize(file.size)}</span></li>`).join('')}</ul></details>`
      : 'The site folder is empty.';
  } catch (e) {
    el.textContent = e.message;
  }
}

const SKIP = /(^|\/)(\.git|\.DS_Store|Thumbs\.db|desktop\.ini|node_modules)(\/|$)/i;

async function upload(name, input, isFolder) {
  const files = [...input.files].filter(file => !SKIP.test(file.webkitRelativePath || file.name));
  input.value = '';
  if (!files.length) return;
  const progress = document.getElementById('upload-progress');
  const replace = document.getElementById('replace').checked;
  try {
    if (replace) await api('DELETE', `${siteUrl(name)}/files`);
    let done = 0;
    for (const file of files) {
      let path = file.webkitRelativePath || file.name;
      // A folder upload includes the folder's own name: drop it, so its index.html lands at the top
      if (isFolder && path.includes('/')) path = path.slice(path.indexOf('/') + 1);
      progress.textContent = `Uploading ${++done} of ${files.length}: ${path}`;
      await api('PUT', `${siteUrl(name)}/files?path=${encodeURIComponent(path)}`, file, true);
    }
    progress.textContent = `Uploaded ${files.length} file${files.length === 1 ? '' : 's'}. Your site is live.`;
  } catch (e) {
    progress.textContent = '';
    toast(e.message, true);
  }
  loadFiles(name);
}

// ---------- theme ----------

// Light by default; the choice is remembered in this browser (index.html applies it before drawing)
const themeToggle = document.getElementById('theme-toggle');

function showTheme() {
  const dark = document.documentElement.dataset.theme === 'dark';
  themeToggle.textContent = dark ? '☀ Light' : '☾ Dark';
  themeToggle.setAttribute('aria-label', dark ? 'Switch to light mode' : 'Switch to dark mode');
}

themeToggle.onclick = () => {
  const dark = document.documentElement.dataset.theme !== 'dark';
  if (dark) document.documentElement.dataset.theme = 'dark';
  else delete document.documentElement.dataset.theme;
  try {
    localStorage.setItem('castell-theme', dark ? 'dark' : 'light');
  } catch (e) {
    // private window or blocked storage: the choice lasts until the page closes
  }
  showTheme();
};

// ---------- start ----------

showTheme();
window.addEventListener('hashchange', route);
refresh().then(route).catch(e => {
  app.innerHTML = `<div class="callout warn"><strong>Castell could not load</strong>${esc(e.message)}</div>`;
});
