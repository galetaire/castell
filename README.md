# Llar

An [umbrelOS community app store](https://github.com/getumbrel/umbrel-community-app-store) with one app:

- **Llar** (`llar-sites`): hosts websites for your **Handshake (HNS)** names on your Umbrel, over HTTPS secured with **DANE** (a `TLSA` record) instead of a certificate authority. *Llar* is Catalan for "home".

One install serves as many names as you like, each either a **static site** (upload a folder) or **another app** (Llar forwards the name to it, for dynamic sites).

## What Llar does for you, and what stays manual

For each name, Llar:

- creates its private key and a 10-year self-signed certificate (or imports a key you already have, so an existing TLSA record stays valid);
- computes the `3 1 1` TLSA value;
- configures Caddy to serve the site, and reloads it;
- shows the exact `A` and `TLSA` records with copy buttons, and the router rule;
- generates `dns-records.txt` and a `README.md` for the site;
- **verifies** the result: the served certificate matches the TLSA value, both records are published and DNSSEC-signed at your DNS host, and the site answers on your public IP.

Three steps happen outside the Umbrel, so they stay manual:

| Step | Where | How often |
|---|---|---|
| Publish the `A` and `TLSA` records | your DNS host (e.g. Yeil) | per name |
| Delegate the name (`NS` + `DS` to your DNS host) | Bob Wallet | once per name |
| Forward TCP 443 → Umbrel:8443 | your router | once, for all names |

## How it works

```
Visitor (DANE-capable Handshake resolver: Fingertip, letsdane)
   │  name -> your public IP            (A record at your DNS host)
   │  checks _443._tcp.name             (TLSA record, DNSSEC-signed)
   ▼
Router :443 ──forward──> Umbrel :8443 ──> Caddy (:443 in the container)
                                            ├─ name1/  static files
                                            └─ name2/  reverse_proxy → another app
```

The app has two containers:

| Container | Role |
|---|---|
| `web` | Llar's UI and API (Node, no dependencies). Owns the data folder: keys, certificates, site files, `state.json`, and the `Caddyfile` it generates. |
| `caddy` | The official Caddy image, published on host port **8443**. Runs with `--watch`, so it reloads whenever Llar rewrites the Caddyfile. Picks each site's certificate by name (SNI). |

TLS ends in Caddy with each site's own key, so nothing in between can re-sign the connection: that's what keeps DANE valid.

**Why port 8443?** umbrelOS uses host port 443 itself. The router maps the public port 443 to 8443, so visitors still connect on 443 and the TLSA name stays `_443._tcp.<name>`. (Mattermost also publishes 8443, so the two can't run together.)

**DNS checks.** Llar asks your DNS host's nameserver directly (default `a.ns.yeil.org`), which answers authoritatively for your zone and shows exactly what you published, signatures included. Public Handshake DNS-over-HTTPS resolvers come and go (as of October 2026, `hnsdoh.com` refuses Handshake names), but you can set one in Llar's settings.

## Security

- Llar is behind your Umbrel login (`app_proxy`), and its server only accepts connections routed by Umbrel, so other apps on the same Umbrel can't reach it directly (same approach as [Bob DNS](https://github.com/galetaire/bob-umbrel)). Requests that change something also need an `X-Llar` header, so other websites open in your browser can't act on Llar.
- Keys never leave the Umbrel unless you download them. Removing a site moves its folder to `trash/` instead of deleting it.

## Repository layout

```
umbrel-app-store.yml               store id + name
llar-sites/                        the Umbrel app (manifest, compose, icon)
docker/Dockerfile                  the web container image
docker/web/server.js               HTTP server and API
docker/web/lib/                    keys and certificates, Caddyfile, DNS client, checks, docs
docker/web/public/                 the UI (plain HTML, CSS and JavaScript)
.github/workflows/build-image.yml  builds and pushes ghcr.io/<owner>/llar (amd64 + arm64)
```

## Publishing

1. Push this repository to `github.com/galetaire/llar`. The workflow builds `ghcr.io/galetaire/llar:<version>` for amd64 and arm64.
2. The first time, open the package on GitHub (**Packages → llar → Package settings**) and set its visibility to **Public**, so Umbrels can pull it without logging in.
3. For a new release: bump `version` in `llar-sites/umbrel-app.yml` **and** the image tag in `llar-sites/docker-compose.yml`, then push.

## Installing

In umbrelOS go to **App Store** → **Community App Stores** → **Manage**, paste `https://github.com/galetaire/llar` and install **Llar**.

## Using it

1. **Your connection** (once): press **Detect** for your public IP, check the Umbrel LAN IP, save.
2. **Router** (once): add the port forward Llar shows.
3. **Add a site**: type the name. For a site that already has a TLSA record, choose its `key.pem` to keep it.
4. Publish the two records it shows at your DNS host; delegate the name in Bob Wallet if you haven't.
5. Upload the site's folder (or point the name at another app).
6. **Run checks.**
7. **Download the key** and keep it somewhere safe.

### Moving a site from a manual Caddy setup

Llar needs host port 8443, so stop the old container first (for example `cd ~/site-DANE && sudo docker compose down`), then add the name in Llar with its existing `key.pem`. The TLSA value comes out the same, so nothing changes at your DNS host. Upload the site files and run the checks.

## Data and backups

Everything is in `~/umbrel/app-data/llar-sites/data` on the Umbrel (`/llar` in the containers):

```
state.json          settings and sites
Caddyfile           generated; don't edit
sites/<name>/       key.pem, cert-<time>.pem, site/
trash/              removed sites
```

**Uninstalling the app deletes this folder, keys included.** Download each site's key from Llar first; a new key means publishing a new TLSA record.

## Local development

```bash
cd docker/web && LLAR_DATA=../../.dev-data PORT=4747 node server.js
```

Open http://localhost:4747. Without a Caddy container the "Caddy serves the site" check fails; to run both, build the image (`docker build -t llar:dev docker`) and use a compose file like `llar-sites/docker-compose.yml` without the `app_proxy` service.

Environment variables: `LLAR_DATA`, `PORT`, `LLAR_HOST_PORT`, `LLAR_CADDY_HOST`, `LLAR_CADDY_PORT`, `LLAR_CADDY_DATA`, `LLAR_IP_SERVICE`, `LLAR_PROXY_HOST`, `LLAR_TRUSTED_IPS`, `LLAR_ALLOW_ANY_SOURCE`.
