'use strict';

// Castell's web UI: plain JavaScript, rendered from the /api/state snapshot.
// Routes: #/ overview, #/add, #/settings, #/site/<name>.
const app = document.getElementById('app');
let data = null;
let currentRoute = '';

// ---------- helpers ----------

const esc = text => String(text ?? '').replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

const ICONS = {
  plus: '<path d="M12 5v14M5 12h14"/>',
  check: '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
  x: '<path d="M7 7l10 10M17 7L7 17"/>',
  bang: '<path d="M12 6v8M12 18h.01"/>',
  alert: '<path d="M12 3l9 16H3z"/><path d="M12 10v4M12 17h.01"/>',
  download: '<path d="M12 4v12M7 11l5 5 5-5M4 20h16"/>',
  upload: '<path d="M12 16V4M7 9l5-5 5 5M4 20h16"/>',
  refresh: '<path d="M20 12a8 8 0 1 1-2.3-5.6M20 4v5h-5"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/>',
  folder: '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
  forward: '<path d="M5 12h14M13 6l6 6-6 6"/>',
  arrow: '<path d="M4 12h16M14 6l6 6-6 6"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M17 6l3 3M15 8l2 2"/>',
  moon: '<path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
};
const icon = (name, extra = '') => `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"${extra}>${ICONS[name]}</svg>`;

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
  const label = button.innerHTML;
  button.disabled = true;
  try {
    await action();
  } catch (e) {
    toast(e.message, true);
  } finally {
    button.disabled = false;
    if (button.isConnected) button.innerHTML = label;
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
const sitePath = name => `#/site/${encodeURIComponent(name)}`;
const lanIp = () => data.settings.lanIp || '<Umbrel LAN IP>';
const capitalize = text => text.charAt(0).toUpperCase() + text.slice(1);
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

function ago(time) {
  const minutes = Math.round((Date.now() - time) / 60000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${plural(minutes, 'minute')} ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${plural(hours, 'hour')} ago`;
  return formatDate(new Date(time).toISOString());
}

// ---------- remembered in this browser ----------

// Check results and key downloads aren't stored on the Umbrel, so this browser
// remembers them to show each site's health. Losing them only means "not checked yet".
function loadStored(key) {
  try {
    return JSON.parse(localStorage.getItem(key)) || {};
  } catch (e) {
    return {};
  }
}
function saveStored(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch (e) {
    // private window or blocked storage: kept until the page closes
  }
}
const checkCache = loadStored('castell-checks');
const keySaved = loadStored('castell-key-saved');
const fileInfo = {};
const ui = {}; // per-site view state: proxy form open, remove confirm open

const WORST = {fail: 3, warn: 2, ok: 1};
function worst(states) {
  return states.reduce((a, b) => ((WORST[b] || 0) > (WORST[a] || 0) ? b : a), 'ok');
}

function siteStatus(name) {
  const cached = checkCache[name];
  if (!cached || !cached.checks.length) return {state: 'unchecked', issues: 0, checks: [], at: null};
  const checks = cached.checks;
  const issues = checks.filter(c => c.status !== 'ok').length;
  return {state: worst(checks.map(c => c.status)), issues, checks, at: cached.at};
}

function statusText(status) {
  if (status.state === 'unchecked') return 'Not checked yet';
  if (status.state === 'ok') return 'All checks pass';
  const okCount = status.checks.length - status.issues;
  return `${okCount} of ${status.checks.length} checks pass`;
}

// ---------- data ----------

async function refresh() {
  data = await api('GET', 'api/state');
  for (const name of Object.keys(checkCache)) {
    if (!data.sites.some(s => s.name === name)) delete checkCache[name];
  }
}

function renderChrome(active) {
  // Server status, in the sidebar and the phone header
  const status = document.getElementById('server-status');
  const mobile = document.getElementById('mobile-status');
  let state, title, detail;
  if (data.caddyListening === null) {
    state = 'unchecked'; title = 'No sites yet'; detail = 'The web server starts with the first site';
  } else if (data.caddyListening) {
    state = 'ok'; title = 'Web server running'; detail = `Caddy on port ${data.hostPort}`;
  } else {
    state = 'fail'; title = 'Web server not reachable'; detail = 'Check the app’s caddy container';
  }
  status.hidden = false;
  status.innerHTML = `<span class="dot ${state}"></span><span><strong>${title}</strong><span class="detail">${detail}</span></span>`;
  mobile.innerHTML = `<span class="dot ${state}"></span>${state === 'ok' ? 'Running' : esc(title)}`;

  // Site list
  const list = document.getElementById('side-sites');
  list.innerHTML = data.sites.length ? data.sites.map(site => {
    const status = siteStatus(site.name);
    const note = status.state === 'unchecked' ? '<span class="note">unchecked</span>'
      : status.issues ? `<span class="note ${status.state}">${plural(status.issues, 'issue')}</span>` : '';
    const current = active === `site:${site.name}` ? ' aria-current="page"' : '';
    return `<li><a class="side-link side-site" href="${sitePath(site.name)}"${current}>
      <span class="dot ${status.state}"></span><span class="name">${esc(site.name)}/</span>${note}</a></li>`;
  }).join('') : '<li class="side-empty">No sites yet</li>';

  for (const link of document.querySelectorAll('[data-nav]')) {
    if (link.dataset.nav === active) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }
}

async function route() {
  const hash = location.hash || '#/';
  const match = /^#\/site\/(.+)$/.exec(hash);
  const name = match && decodeURIComponent(match[1]);
  // A site added elsewhere (another tab) since this page loaded
  if (name && !data.sites.some(s => s.name === name)) await refresh().catch(() => {});
  const site = name && data.sites.find(s => s.name === name);
  const changed = hash !== currentRoute;
  currentRoute = hash;

  if (site) renderSite(site);
  else if (hash === '#/add') renderAdd();
  else if (hash === '#/settings') renderSettings();
  else renderOverview();

  closeMenu();
  if (changed) {
    window.scrollTo(0, 0);
    app.focus({preventScroll: true});
  }
}

// ---------- overview ----------

function segments(status, count = 4) {
  const cells = status.checks.length ? status.checks.map(c => c.status) : Array(count).fill('');
  return `<div class="segments" style="grid-template-columns: repeat(${cells.length}, minmax(0, 1fr))" aria-hidden="true">
    ${cells.map(s => `<span class="${s}"></span>`).join('')}</div>`;
}

function renderOverview() {
  renderChrome('overview');
  const {settings, sites} = data;
  const banners = [];

  if (!settings.publicIp) {
    banners.push(`
      <section class="card banner">
        <span class="banner-icon info">${icon('info')}</span>
        <div class="banner-body"><h2>Finish the one-time setup</h2>
          <p>Set your public IP and add the router rule, so your sites can be reached.</p></div>
        <a class="button ink" href="#/settings">Set up</a>
      </section>`);
  }
  for (const site of sites) {
    const status = siteStatus(site.name);
    if (status.state !== 'fail' && status.state !== 'warn') continue;
    const first = status.checks.find(c => c.status === status.state);
    banners.push(`
      <section class="card banner${status.state === 'fail' ? ' attention' : ''}">
        <span class="banner-icon ${status.state}">${icon('alert')}</span>
        <div class="banner-body"><h2>${esc(site.name)}/: ${esc(first.label)}</h2><p>${esc(capitalize(first.detail))}</p></div>
        <a class="button ink" href="${sitePath(site.name)}">${status.state === 'fail' ? 'Fix it' : 'Review'}</a>
      </section>`);
  }

  const cards = sites.map(site => {
    const status = siteStatus(site.name);
    const meta = site.mode === 'proxy'
      ? `<span class="mono">→ ${esc(site.upstream)}</span>`
      : `<span>${site.cert ? `Certificate until ${formatDate(site.cert.validTo)}` : ''}</span>`;
    return `<a class="site-card" href="${sitePath(site.name)}">
      <span class="site-card-top"><span class="site-card-name">${esc(site.name)}/</span>
        <span class="badge small">${site.mode === 'proxy' ? 'app' : 'static'}</span></span>
      ${segments(status)}
      <span class="site-card-foot"><span class="status-text ${status.state}">${statusText(status)}</span>${meta}</span>
    </a>`;
  }).join('');

  app.innerHTML = `<div class="page">
    <div class="page-head">
      <div><h1>Overview</h1>
        <p>${sites.length ? `${plural(sites.length, 'Handshake name')} served from this Umbrel` : 'Host websites for your Handshake names, secured with DANE.'}</p></div>
      <a class="button primary" href="#/add">${icon('plus')}Add a site</a>
    </div>

    ${banners.join('')}

    ${sites.length ? `
    <section aria-labelledby="sites-h">
      <h2 class="section-label" id="sites-h">Sites</h2>
      <div class="site-grid">${cards}
        <a class="button add-card" href="#/add">${icon('plus')}Add a Handshake name</a>
      </div>
    </section>` : `
    <section class="card empty">
      <h2>No sites yet</h2>
      <p class="muted">Add a Handshake name you own. Castell creates its key and certificate and shows the records to publish.</p>
      <div class="actions" style="justify-content: center; margin-top: 14px"><a class="button primary" href="#/add">${icon('plus')}Add your first site</a></div>
    </section>`}

    <section class="card" aria-labelledby="setup-h">
      <div class="card-head"><h2 id="setup-h" style="font-size: 16px">Shared setup</h2><a href="#/settings" style="font-weight: 600; font-size: 14px">Edit</a></div>
      <dl class="facts">
        <div><dt>Public IP</dt><dd>${esc(settings.publicIp || 'Not set')}</dd></div>
        <div><dt>Router rule</dt><dd>443 → ${esc(lanIp())}:${data.hostPort}</dd></div>
        <div><dt>Checks ask</dt><dd>${esc(settings.dnsServer)}</dd></div>
      </dl>
    </section>
  </div>`;
}

// ---------- add a site ----------

function renderAdd() {
  renderChrome('add');
  const {settings} = data;
  app.innerHTML = `<div class="page">
    <div class="page-head"><div>
      <nav class="crumbs" aria-label="Breadcrumb"><a href="#/">Overview</a> / New site</nav>
      <h1 style="margin-top: 4px">Add a site</h1>
      <p>One Handshake name, served from this Umbrel over DANE.</p>
    </div></div>

    <div class="columns">
      <form class="card stack col-main" id="add-form" novalidate>
        <div>
          <label class="field" for="add-name">Handshake name</label>
          <span class="hint">The name you own. Subdomains like <code>www.mysite</code> are served automatically.</span>
          <div class="name-input">
            <input type="text" id="add-name" required autocomplete="off" spellcheck="false" placeholder="mysite">
            <span aria-hidden="true">/</span>
          </div>
        </div>

        <fieldset>
          <legend>What it serves</legend>
          <div class="options">
            <label class="option">
              <span class="option-top"><span class="option-icon">${icon('folder')}</span><input type="radio" name="mode" value="static" checked></span>
              <strong>Static website</strong>
              <span class="desc">Upload a folder of HTML, CSS and images. Castell serves it.</span>
            </label>
            <label class="option">
              <span class="option-top"><span class="option-icon">${icon('forward')}</span><input type="radio" name="mode" value="proxy"></span>
              <strong>Another app</strong>
              <span class="desc">Forward the name to an app on your network, for dynamic sites.</span>
            </label>
          </div>
          <div id="add-upstream" hidden style="margin-top: 16px">
            <label class="field" for="add-upstream-input">App address</label>
            <span class="hint">Where the app listens, as host:port, e.g. <code>${esc(settings.lanIp || '192.168.1.27')}:3000</code>.</span>
            <input type="text" id="add-upstream-input" autocomplete="off" spellcheck="false" placeholder="${esc(settings.lanIp || '192.168.1.27')}:3000" style="max-width: 440px">
          </div>
        </fieldset>

        <div>
          <span class="field-label">Existing key <span class="muted" style="font-weight: 400">(optional)</span></span>
          <span class="hint">Moving a site that already has a TLSA record? Choose its key.pem so the record stays valid.</span>
          <div class="file-row">
            <button type="button" id="choose-key">${icon('key')}Choose key.pem</button>
            <input type="file" id="add-key" accept=".pem,.key,text/plain" hidden>
            <span class="muted small" id="key-name">None chosen: Castell creates a new key</span>
          </div>
        </div>

        <div class="actions end">
          <button class="primary" type="submit" id="add-submit">Add site</button>
          <a class="button" href="#/">Cancel</a>
        </div>
      </form>

      <aside class="card dark col-side" aria-labelledby="next-h">
        <h2 id="next-h" style="margin-bottom: 14px">What Castell does next</h2>
        <ol class="steps-list">
          <li><span class="n">1</span><span>Creates a private key and a 10-year certificate, or uses the key you chose</span></li>
          <li><span class="n">2</span><span>Works out the <code>3 1 1</code> TLSA value</span></li>
          <li><span class="n">3</span><span>Sets up Caddy to serve the name</span></li>
          <li><span class="n">4</span><span>Shows the A and TLSA records to publish at your DNS host</span></li>
        </ol>
        <p class="foot">You’ll still publish the records, delegate the name in Bob Wallet, and forward the router port yourself.</p>
      </aside>
    </div>
  </div>`;

  const nameInput = document.getElementById('add-name');
  const submit = document.getElementById('add-submit');
  nameInput.oninput = () => {
    const name = nameInput.value.trim().replace(/\/+$/, '');
    submit.textContent = name ? `Add ${name}/` : 'Add site';
  };
  for (const radio of app.querySelectorAll('input[name="mode"]')) {
    radio.onchange = () => {
      document.getElementById('add-upstream').hidden = radio.value !== 'proxy' || !radio.checked;
    };
  }
  const keyInput = document.getElementById('add-key');
  document.getElementById('choose-key').onclick = () => keyInput.click();
  keyInput.onchange = () => {
    const file = keyInput.files[0];
    document.getElementById('key-name').textContent = file ? `${file.name}: keeps the existing TLSA record` : 'None chosen: Castell creates a new key';
  };

  document.getElementById('add-form').onsubmit = event => {
    event.preventDefault();
    if (!nameInput.value.trim()) {
      nameInput.focus();
      toast('Type the Handshake name first.', true);
      return;
    }
    busy(submit, async () => {
      submit.textContent = 'Creating key and certificate…';
      const mode = app.querySelector('input[name="mode"]:checked').value;
      const keyFile = keyInput.files[0];
      const site = await api('POST', 'api/sites', {
        name: nameInput.value.trim().replace(/\/+$/, ''),
        mode,
        upstream: document.getElementById('add-upstream-input').value,
        keyPem: keyFile ? await keyFile.text() : undefined,
      });
      await refresh();
      toast(`${site.name}/ added. Next: publish its records.`);
      location.hash = sitePath(site.name);
    });
  };
  nameInput.focus();
}

// ---------- connection and router ----------

function routerStatus() {
  const results = data.sites.map(s => siteStatus(s.name).checks.find(c => c.id === 'public')).filter(Boolean);
  if (results.some(c => c.status === 'ok')) return {cls: 'ok', icon: 'check', text: 'Working: a site answered on 443'};
  if (results.some(c => c.status === 'fail')) return {cls: 'fail', icon: 'x', text: 'Another device answers on 443'};
  if (results.length) return {cls: 'warn', icon: 'bang', text: 'Not confirmed from inside your network'};
  return {cls: 'idle', icon: 'info', text: 'Not tested yet'};
}

function renderSettings() {
  renderChrome('settings');
  const {settings} = data;
  // The browser reached Castell through the Umbrel's LAN address: a good guess for the router rule
  const suggestedLan = !settings.lanIp && IPV4_RE.test(location.hostname) ? location.hostname : '';
  const router = routerStatus();

  app.innerHTML = `<div class="page">
    <div class="page-head"><div><h1>Connection &amp; router</h1><p>Set once. Every site uses these.</p></div></div>

    <form id="settings-form" class="page" style="gap: 22px">
      <section class="card" aria-labelledby="net-h">
        <h2 id="net-h" style="margin-bottom: 16px">Your connection</h2>
        <div class="grid-fields">
          <div>
            <label class="field" for="set-public">Public IP</label>
            <span class="hint">Your home’s internet address. It goes in each site’s A record.</span>
            <div class="input-row">
              <input type="text" id="set-public" value="${esc(settings.publicIp)}" placeholder="203.0.113.7" spellcheck="false">
              <button type="button" id="detect-ip">Detect</button>
            </div>
          </div>
          <div>
            <label class="field" for="set-lan">Umbrel LAN IP</label>
            <span class="hint">This Umbrel on your home network${suggestedLan ? ' (filled in from your browser’s address)' : ''}. Reserve it in your router’s DHCP settings.</span>
            <input type="text" id="set-lan" value="${esc(settings.lanIp || suggestedLan)}" placeholder="192.168.1.27" spellcheck="false">
          </div>
        </div>
      </section>

      <section class="card" aria-labelledby="router-h">
        <div class="card-head">
          <h2 id="router-h">Router: one rule for all sites</h2>
          <span class="pill ${router.cls}">${icon(router.icon)}${router.text}</span>
        </div>
        <p class="lead" style="margin-top: 6px">Add this port forward in your router, often under Port forwarding, Virtual server or NAT.</p>
        <div class="route">
          <div><span class="k">From the internet</span><span class="v">TCP 443</span></div>
          <div class="arrow">${icon('arrow')}</div>
          <div><span class="k">To this Umbrel</span><span class="v">${esc(lanIp())}:${data.hostPort}</span></div>
        </div>
        <p class="muted small" style="margin-top: 12px">umbrelOS uses port 443 itself, so Castell listens on ${data.hostPort}. Visitors still connect on 443.
          Leave any “remote host” field empty, and enable the rule after saving.</p>
      </section>

      <section class="card" aria-labelledby="dns-h">
        <h2 id="dns-h">DNS checks</h2>
        <label class="field" for="set-dns" style="margin-top: 14px">Nameserver to ask</label>
        <span class="hint">Your DNS host’s nameserver shows exactly what you published (Yeil: <code>a.ns.yeil.org</code>). A Handshake DNS-over-HTTPS URL also works.</span>
        <input type="text" id="set-dns" value="${esc(settings.dnsServer)}" spellcheck="false" style="max-width: 440px">
      </section>

      <div class="actions">
        <button class="primary" type="submit">Save changes</button>
        <a class="button" href="#/">Cancel</a>
      </div>
    </form>
  </div>`;

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
      renderSettings();
      toast('Saved.');
    });
  };
}

// ---------- site ----------

const STATE_LABEL = {ok: 'Done', warn: 'Check', fail: 'Fix', todo: 'To do', manual: 'Manual'};

function siteSteps(site, status) {
  const byId = Object.fromEntries(status.checks.map(c => [c.id, c]));
  const has = id => Boolean(byId[id]);
  const records = has('dns-a') && has('dns-tlsa') ? worst([byId['dns-a'].status, byId['dns-tlsa'].status]) : 'todo';
  const router = has('public') ? byId.public.status : 'todo';
  let content = 'todo';
  if (site.mode === 'proxy') {
    content = has('caddy') ? byId.caddy.status : 'todo';
  } else if (fileInfo[site.name]) {
    const {files, hasIndex} = fileInfo[site.name];
    content = hasIndex ? 'ok' : files.length ? 'warn' : 'todo';
  }
  const live = status.state === 'ok' ? 'ok' : 'todo';
  return [
    {name: 'DNS records', state: records},
    {name: 'Delegation', state: 'manual'},
    {name: 'Router', state: router},
    {name: 'Content', state: content},
    {name: 'Live with DANE', state: live},
  ];
}

function recordCard(type, name, value, check, missingValue) {
  let cls = '', label = 'Not checked', note = '';
  if (missingValue) {
    cls = 'warn'; label = 'Needs your public IP';
    note = '<p>Set your public IP on the <a href="#/settings">Connection page</a> first.</p>';
  } else if (check) {
    cls = check.status;
    label = check.status === 'ok' ? 'Published, signed'
      : check.status === 'warn' ? 'Needs attention'
        : /^no /.test(check.detail) ? 'Not found' : 'Wrong value';
    if (check.status !== 'ok') note = `<p>${esc(capitalize(check.detail))}</p>`;
  }
  const statusIcon = {ok: 'check', warn: 'bang', fail: 'x'}[cls];
  return `<div class="record ${cls === 'ok' ? '' : cls}">
    <div class="record-head"><span class="rtype">${type}</span><span class="mono">${esc(name)}</span>
      <span class="status-text ${cls || 'unchecked'}">${statusIcon ? icon(statusIcon) : ''}${label}</span></div>
    <div class="record-value"><code>${esc(value)}</code>
      <button type="button" class="icon-only" data-copy="${esc(value)}" aria-label="Copy ${type} record value">${icon('copy')}</button></div>
    ${note}
  </div>`;
}

function contentSection(site) {
  const name = site.name;
  const state = ui[name] || {};
  if (site.mode === 'proxy') {
    return `<section class="card" aria-labelledby="content-h">
      <div class="card-head"><h2 id="content-h">Content</h2>
        <button type="button" class="link" id="to-static">Serve static files instead</button></div>
      <p class="lead" style="margin-top: 6px">Requests for <strong>${esc(name)}/</strong> go to this app:</p>
      <label class="visually-hidden" for="upstream">App address</label>
      <div class="input-row" style="max-width: 520px">
        <input type="text" id="upstream" value="${esc(site.upstream)}" spellcheck="false">
        <button type="button" id="save-upstream">Save</button>
      </div>
      <p class="muted small" style="margin-top: 10px">Use an address the Umbrel can reach, e.g. <code>${esc(data.settings.lanIp || '192.168.1.27')}:3000</code> for an app published on that port.</p>
    </section>`;
  }

  const info = fileInfo[name];
  let summary = '<span class="muted">Loading files…</span>';
  if (info && info.error) summary = `<span class="status-text fail">${esc(info.error)}</span>`;
  else if (info && !info.files.length) summary = '<span class="muted">The site folder is empty.</span>';
  else if (info) {
    summary = `${info.hasIndex
      ? `<span class="status-text ok">${icon('check')}index.html found</span>`
      : `<span class="status-text warn">${icon('bang')}No index.html at the top</span>`}
      <span class="muted">${plural(info.files.length, 'file')} · ${formatSize(info.total)}</span>
      <button type="button" class="link push" id="toggle-files" aria-expanded="${Boolean(state.showFiles)}">${state.showFiles ? 'Hide files' : 'Show files'}</button>`;
  }

  return `<section class="card" aria-labelledby="content-h">
    <div class="card-head"><h2 id="content-h">Content</h2>
      <button type="button" class="link" id="to-proxy" aria-expanded="${Boolean(state.proxyForm)}">Serve another app instead</button></div>
    ${state.proxyForm ? `
      <form id="proxy-form" class="file-row" style="margin-top: 14px">
        <label class="visually-hidden" for="proxy-upstream">App address</label>
        <input type="text" id="proxy-upstream" placeholder="${esc(data.settings.lanIp || '192.168.1.27')}:3000" spellcheck="false" style="flex: 1 1 200px; width: auto">
        <button type="submit" class="ink">Forward to app</button>
        <button type="button" id="proxy-cancel">Cancel</button>
      </form>` : ''}
    <div class="dropzone" id="dropzone">
      <span class="dropzone-icon">${icon('folder')}</span>
      <div class="dropzone-text"><strong>Drop your site’s folder here</strong><span>Its index.html becomes the home page</span></div>
      <div class="actions">
        <button type="button" class="ink" id="pick-folder">Choose folder</button>
        <button type="button" id="pick-files">Files</button>
      </div>
      <input type="file" id="upload-folder" webkitdirectory multiple hidden>
      <input type="file" id="upload-files" multiple hidden>
    </div>
    <label class="check-label" style="margin-top: 12px"><input type="checkbox" id="replace" checked> Replace the current site (removes files not in the upload)</label>
    <p id="upload-progress" class="small muted" role="status"></p>
    <div class="file-summary">${summary}</div>
    ${info && info.files && state.showFiles ? `<ul class="files">${info.files.map(file =>
      `<li><span class="mono">${esc(file.path)}</span> <span class="muted">${formatSize(file.size)}</span></li>`).join('')}</ul>` : ''}
  </section>`;
}

function checksCard(status) {
  if (!status.checks.length) {
    return `<section class="card" aria-labelledby="checks-h">
      <h2 id="checks-h">Checks</h2>
      <p class="muted small" style="margin-top: 8px">Not checked yet. Run checks to test the certificate, both DNS records and your public address.</p>
    </section>`;
  }
  const okCount = status.checks.filter(c => c.status === 'ok').length;
  const icons = {ok: 'check', warn: 'bang', fail: 'x'};
  return `<section class="card" aria-labelledby="checks-h">
    <div class="card-head"><h2 id="checks-h">Checks</h2><span class="muted small">${ago(status.at)}</span></div>
    <div class="score"><strong>${okCount}<span>/${status.checks.length}</span></strong><span>passing</span></div>
    <ul class="checks">${status.checks.map(check => `
      <li><span class="check-icon ${check.status}">${icon(icons[check.status], ' style="stroke-width: 3.5"')}</span>
        <span><strong>${esc(check.label)}</strong><span class="detail">${esc(capitalize(check.detail))}</span></span></li>`).join('')}
    </ul>
    <p class="muted small" style="margin-top: 10px">DNS changes can take a while to show up.</p>
  </section>`;
}

function renderSite(site) {
  const name = site.name;
  renderChrome(`site:${name}`);
  const {settings} = data;
  const status = siteStatus(name);
  const byId = Object.fromEntries(status.checks.map(c => [c.id, c]));
  const steps = siteSteps(site, status);
  const saved = keySaved[name];
  const state = ui[name] || (ui[name] = {});

  app.innerHTML = `<div class="page">
    <div class="page-head">
      <div style="min-width: 0">
        <nav class="crumbs" aria-label="Breadcrumb"><a href="#/">Overview</a> / Sites</nav>
        <div class="title-row">
          <h1 class="site-title">${esc(name)}/</h1>
          <span class="badge">${site.mode === 'proxy' ? 'app' : 'static site'}</span>
          ${site.keyImported ? '<span class="badge">imported key</span>' : ''}
        </div>
      </div>
      <div class="actions">
        ${saved ? '' : `<a class="button" href="${siteUrl(name)}/download/key" download data-key-download>${icon('download')}Back up key</a>`}
        <button type="button" class="primary" id="verify">${icon('refresh')}Run checks</button>
      </div>
    </div>

    <ol class="progress" aria-label="Setup progress">${steps.map((step, i) => `
      <li class="${step.state}"><span class="bar"></span>
        <span class="state">Step ${i + 1} · ${STATE_LABEL[step.state]}</span><span class="name">${step.name}</span></li>`).join('')}
    </ol>

    <div class="columns">
      <div class="col-main">
        <section class="card" aria-labelledby="rec-h">
          <h2 id="rec-h">Publish at your DNS host</h2>
          <p class="lead">In the <span class="mono">${esc(name)}</span> zone. Castell checks <span class="mono">${esc(settings.dnsServer)}</span>.</p>
          <div class="records">
            ${recordCard('A', '@', settings.publicIp || '<your public IP>', byId['dns-a'], !settings.publicIp)}
            ${recordCard('TLSA', '_443._tcp', `3 1 1 ${site.tlsa}`, byId['dns-tlsa'], false)}
          </div>
          <p class="muted small" style="margin-top: 12px">At Yeil, the TLSA name is entered as <code>_443._tcp</code> inside the <code>${esc(name)}</code> zone. Publish it before sharing the site.</p>
          <details class="more">
            <summary>Delegate the name in Bob Wallet (once per name)</summary>
            <p>In <strong>Bob Wallet → Domain Manager → ${esc(name)}</strong>, add the two <code>NS</code> records and the <code>DS</code> record your DNS host gives you
              (Yeil: <code>a.ns.yeil.org.</code> and <code>b.ns.yeil.org.</code>). Castell can’t check this step; the DNS checks only pass with DNSSEC once it’s done.</p>
          </details>
          <details class="more">
            <summary>Router rule (shared by all sites)</summary>
            <p>TCP 443 → <span class="mono">${esc(lanIp())}:${data.hostPort}</span>. <a href="#/settings">Connection &amp; router</a> has the details.</p>
          </details>
        </section>

        ${contentSection(site)}
      </div>

      <div class="col-side">
        ${checksCard(status)}

        ${saved ? `
        <section class="card" aria-labelledby="key-h">
          <h2 id="key-h" style="font-size: 16px">Key</h2>
          <p class="muted small" style="margin: 4px 0 12px">Downloaded from this browser on ${formatDate(saved)}. Keep it somewhere safe: the TLSA record depends on it.</p>
          <a class="button" href="${siteUrl(name)}/download/key" download data-key-download>${icon('download')}Download key.pem again</a>
        </section>` : `
        <section class="card dark" aria-labelledby="key-h">
          <h2 id="key-h">Your key isn’t backed up</h2>
          <p style="margin: 6px 0 14px">The TLSA record depends on this key. If you uninstall Castell or lose the Umbrel, the key is gone and you’d need a new TLSA record.</p>
          <a class="button" href="${siteUrl(name)}/download/key" download data-key-download>${icon('download')}Download key.pem</a>
        </section>`}

        <section class="card" aria-labelledby="cert-h">
          <h2 id="cert-h" style="font-size: 16px">Certificate</h2>
          <p class="muted small" style="margin: 4px 0 12px">Valid until <strong style="color: var(--text)">${site.cert ? formatDate(site.cert.validTo) : 'unknown'}</strong>. Reissuing keeps the key and the TLSA record.</p>
          <div class="downloads">
            <a href="${siteUrl(name)}/download/records" download>dns-records.txt<span aria-hidden="true">${icon('download')}</span></a>
            <a href="${siteUrl(name)}/download/readme" download>README.md<span aria-hidden="true">${icon('download')}</span></a>
            <a href="${siteUrl(name)}/download/cert" download>cert.pem<span aria-hidden="true">${icon('download')}</span></a>
          </div>
          <div class="actions" style="margin-top: 14px">
            <button type="button" id="renew">Reissue</button>
            <button type="button" class="danger" id="remove" aria-expanded="${Boolean(state.confirmRemove)}">Remove site…</button>
          </div>
          ${state.confirmRemove ? `
          <div class="confirm" role="group" aria-label="Confirm removal">
            <p><strong>Remove ${esc(name)}/ from Castell?</strong> It stops being served. Its key and files move to the trash folder in Castell’s data on the Umbrel; nothing is deleted.</p>
            <div class="actions"><button type="button" class="danger solid" id="remove-confirm">Remove ${esc(name)}/</button>
              <button type="button" id="remove-cancel">Keep it</button></div>
          </div>` : ''}
        </section>
      </div>
    </div>
  </div>`;

  // Copy buttons
  for (const button of app.querySelectorAll('[data-copy]')) {
    button.onclick = async () => {
      await copyText(button.dataset.copy);
      button.innerHTML = icon('check');
      toast('Copied.');
      setTimeout(() => button.isConnected && (button.innerHTML = icon('copy')), 1500);
    };
  }

  // Remembering the key download
  for (const link of app.querySelectorAll('[data-key-download]')) {
    link.addEventListener('click', () => {
      keySaved[name] = new Date().toISOString();
      saveStored('castell-key-saved', keySaved);
      setTimeout(() => currentRoute === location.hash && renderSite(site), 300);
    });
  }

  const setMode = (button, modeBody, message) => busy(button, async () => {
    await api('PATCH', siteUrl(name), modeBody);
    state.proxyForm = false;
    await refresh();
    route();
    toast(message);
  });

  if (site.mode === 'proxy') {
    document.getElementById('save-upstream').onclick = event => setMode(event.currentTarget,
      {mode: 'proxy', upstream: document.getElementById('upstream').value}, 'Saved. Caddy reloads in a few seconds.');
    document.getElementById('to-static').onclick = event => setMode(event.currentTarget, {mode: 'static'}, 'Now serving the static files.');
  } else {
    if (!fileInfo[name]) loadFiles(name);
    const folderInput = document.getElementById('upload-folder');
    const filesInput = document.getElementById('upload-files');
    document.getElementById('pick-folder').onclick = () => folderInput.click();
    document.getElementById('pick-files').onclick = () => filesInput.click();
    folderInput.onchange = () => uploadFromInput(name, folderInput, true);
    filesInput.onchange = () => uploadFromInput(name, filesInput, false);

    const zone = document.getElementById('dropzone');
    zone.ondragover = event => {
      event.preventDefault();
      zone.classList.add('over');
    };
    zone.ondragleave = () => zone.classList.remove('over');
    zone.ondrop = event => {
      event.preventDefault();
      zone.classList.remove('over');
      const pending = filesFromDrop(event.dataTransfer);
      pending.then(list => uploadList(name, list)).catch(e => toast(e.message, true));
    };

    const toggle = document.getElementById('toggle-files');
    if (toggle) toggle.onclick = () => {
      state.showFiles = !state.showFiles;
      renderSite(site);
    };
    document.getElementById('to-proxy').onclick = () => {
      state.proxyForm = !state.proxyForm;
      renderSite(site);
      if (state.proxyForm) document.getElementById('proxy-upstream').focus();
    };
    const proxyForm = document.getElementById('proxy-form');
    if (proxyForm) {
      proxyForm.onsubmit = event => {
        event.preventDefault();
        const upstream = document.getElementById('proxy-upstream').value.trim();
        if (!upstream) return toast('Type the app’s address, as host:port.', true);
        setMode(event.submitter, {mode: 'proxy', upstream}, 'Now forwarding to the app.');
      };
      document.getElementById('proxy-cancel').onclick = () => {
        state.proxyForm = false;
        renderSite(site);
      };
    }
  }

  document.getElementById('verify').onclick = event => busy(event.currentTarget, async () => {
    event.currentTarget.innerHTML = `${icon('refresh')}Checking…`;
    const {checks} = await api('POST', `${siteUrl(name)}/verify`);
    checkCache[name] = {checks, at: Date.now()};
    saveStored('castell-checks', checkCache);
    if (currentRoute === sitePath(name)) renderSite(site);
    const failing = checks.filter(c => c.status !== 'ok').length;
    toast(failing ? `${plural(failing, 'check')} need attention.` : 'All checks pass.');
  });

  document.getElementById('renew').onclick = event => busy(event.currentTarget, async () => {
    await api('POST', `${siteUrl(name)}/renew`);
    await refresh();
    route();
    toast('New certificate issued with the same key. Your TLSA record is unchanged.');
  });

  document.getElementById('remove').onclick = () => {
    state.confirmRemove = !state.confirmRemove;
    renderSite(site);
    const confirmButton = document.getElementById('remove-confirm');
    if (confirmButton) confirmButton.focus();
  };
  const confirmButton = document.getElementById('remove-confirm');
  if (confirmButton) {
    confirmButton.onclick = event => busy(event.currentTarget, async () => {
      await api('DELETE', siteUrl(name));
      delete checkCache[name];
      saveStored('castell-checks', checkCache);
      delete ui[name];
      delete fileInfo[name];
      await refresh();
      location.hash = '#/';
      toast(`${name}/ removed.`);
    });
    document.getElementById('remove-cancel').onclick = () => {
      state.confirmRemove = false;
      renderSite(site);
    };
  }
}

async function loadFiles(name) {
  try {
    const {files} = await api('GET', `${siteUrl(name)}/files`);
    fileInfo[name] = {
      files,
      total: files.reduce((sum, file) => sum + file.size, 0),
      hasIndex: files.some(file => file.path === 'index.html'),
    };
  } catch (e) {
    fileInfo[name] = {error: e.message};
  }
  const site = data.sites.find(s => s.name === name);
  if (site && currentRoute === sitePath(name)) renderSite(site);
}

// ---------- uploads ----------

const SKIP = /(^|\/)(\.git|\.DS_Store|Thumbs\.db|desktop\.ini|node_modules)(\/|$)/i;

function uploadFromInput(name, input, isFolder) {
  const list = [...input.files].map(file => {
    let path = file.webkitRelativePath || file.name;
    // A folder upload includes the folder's own name: drop it, so its index.html lands at the top
    if (isFolder && path.includes('/')) path = path.slice(path.indexOf('/') + 1);
    return {file, path};
  });
  input.value = '';
  uploadList(name, list);
}

// Files and folders dropped on the drop zone. A single folder is uploaded as its contents.
function filesFromDrop(dataTransfer) {
  // Entries must be read before the first await: the drop data is only valid during the event
  const entries = [...dataTransfer.items].map(item => item.webkitGetAsEntry && item.webkitGetAsEntry()).filter(Boolean);
  const plainFiles = [...dataTransfer.files];
  return (async () => {
    if (!entries.length) return plainFiles.map(file => ({file, path: file.name}));
    const out = [];
    async function walk(entry, prefix) {
      if (entry.isFile) {
        const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
        out.push({file, path: prefix + entry.name});
      } else if (entry.isDirectory) {
        const reader = entry.createReader();
        let batch;
        do {
          batch = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
          for (const child of batch) await walk(child, `${prefix}${entry.name}/`);
        } while (batch.length);
      }
    }
    for (const entry of entries) await walk(entry, '');
    if (entries.length === 1 && entries[0].isDirectory) {
      const top = `${entries[0].name}/`;
      for (const item of out) item.path = item.path.slice(top.length);
    }
    return out;
  })();
}

async function uploadList(name, list) {
  const files = list.filter(item => !SKIP.test(item.path));
  if (!files.length) return;
  const progress = document.getElementById('upload-progress');
  const replace = document.getElementById('replace').checked;
  try {
    if (replace) await api('DELETE', `${siteUrl(name)}/files`);
    let done = 0;
    for (const {file, path} of files) {
      if (progress.isConnected) progress.textContent = `Uploading ${++done} of ${files.length}: ${path}`;
      await api('PUT', `${siteUrl(name)}/files?path=${encodeURIComponent(path)}`, file, true);
    }
    toast(`Uploaded ${plural(files.length, 'file')}. Your site is live.`);
  } catch (e) {
    toast(e.message, true);
  }
  if (progress.isConnected) progress.textContent = '';
  await loadFiles(name);
}

// ---------- menu and theme ----------

const menuButton = document.getElementById('menu-button');
const side = document.getElementById('side');
function closeMenu() {
  side.classList.remove('open');
  menuButton.setAttribute('aria-expanded', 'false');
  menuButton.setAttribute('aria-label', 'Open menu');
}
menuButton.onclick = () => {
  const open = !side.classList.contains('open');
  side.classList.toggle('open', open);
  menuButton.setAttribute('aria-expanded', String(open));
  menuButton.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
};

// Light by default; the choice is remembered in this browser (index.html applies it before drawing)
const themeToggle = document.getElementById('theme-toggle');

function showTheme() {
  const dark = document.documentElement.dataset.theme === 'dark';
  themeToggle.innerHTML = dark ? `${icon('sun')}Light mode` : `${icon('moon')}Dark mode`;
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
  app.innerHTML = `<div class="card banner attention"><span class="banner-icon fail">${icon('alert')}</span>
    <div class="banner-body"><h2>Castell could not load</h2><p>${esc(e.message)}</p></div></div>`;
});
