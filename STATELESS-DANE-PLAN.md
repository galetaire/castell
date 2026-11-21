# Plan: Stateless DANE proofs in Castell's site certificates

Handoff from the Dit session (21 Nov 2026). Goal: every site Castell hosts
serves a certificate that carries its own **HIP-17 Stateless DANE proofs**, so
clients can verify it from the Handshake blockchain without any DNS lookups.
Nothing is built yet in Castell. Commit/push only when the owner asks.

## Background in one paragraph

Today a Castell site is plain DANE: a self-signed certificate (EC P-256, 10
years, `docker/web/lib/certs.js` `issueCert`) whose key is pinned by a
`3 1 1` TLSA record in the site's DNSSEC-signed zone. A Stateless DANE
certificate ([HIP-17](https://hsd-dev.org/HIPs/proposals/0017/)) is the same
certificate plus two extensions holding the proofs. Normal browsers and
letsdane/Dit's proxy ignore them, so adding them changes nothing for current
visitors; SANE clients (randomlogin/sane) and Dit's checker read them.

## What goes into the certificate

Two non-critical X.509 extensions. These are the IDs both existing
implementations use (htools-org/stateless-dane `lib/extensions.js`,
randomlogin/sane `prove/prove.go`); HIP-17 itself still says "TBD":

| Extension ID | extnValue (raw bytes inside the OCTET STRING) |
|---|---|
| `1.3.6.1.4.1.54392.5.1620` | **Urkel proof:** 1 byte proof count, then per proof a 32-byte tree root + the Urkel proof (urkel encoding, BLAKE2b-256, key = SHA3-256 of the top-level name) proving the TLD's on-chain state with its DS record |
| `1.3.6.1.4.1.54392.5.1621` | **DNSSEC chain:** 2 bytes port (443 = `01bb`), 2 bytes lifetime (`0000`), then wire-format DNS records: DNSKEY sets, DS of sub-zones, the `_443._tcp.<name>` TLSA set, all with their RRSIGs |

## Where the proofs come from

**Phase 1: public proof services** (both work, verified 20–21 Nov 2026):

```
GET https://sdaneproofs.htools.work/proofs/<name>?urkel   -> {"urkel":  "<hex>"}
GET https://sdaneproofs.htools.work/proofs/<name>?dnssec  -> {"dnssec": "<hex>"}
fallback: https://sdaneproofs.woodburn.au/proofs/<name>?...
```

The hex values are **exactly** the two extnValue byte strings above: decode
and embed as they are. Names without a TLSA record get HTTP 500. The proofs
are self-verifying (the Urkel proof is checked against tree roots the client
synced itself, the chain against the DS in that proof), so Castell does not
have to trust the service; only availability depends on it.

Note: the services anchor to the tree root from about **8 days ago** (HIP-17's
"32nd most recent root"); clients keep about two weeks of roots.

**Phase 2 (optional, later): own node.** The owner's Bob DNS app
(galetaire/bob-dns) runs a full hsd node on the same Umbrel and exposes a
read-only node API (for Finestra). hsd's `getnameproof <tld> [root]` RPC gives
the Urkel proof; the htools generator builds the blob like this
(`lib/index.js` `_getUrkelProofExtension`): proof at the root from ~32 tree
intervals back, plus a second proof at the newer root if the name was
UPDATEd recently. The DNSSEC chain needs a validating resolver walk (htools
uses `delv +rtrace +mtrace` against hnsd with the Handshake KSK). Check first
whether Bob DNS's API allows `getnameproof`.

## How to embed with openssl (no new dependencies)

Castell already issues with `openssl req -x509 -new -key …`. Add the two
extensions with openssl's arbitrary-extension syntax, `OID=DER:<hex>`, which
puts those bytes verbatim as the extnValue. The hex is a few KB, so pass it
through a config file rather than `-addext` on the command line:

```
[ext]
subjectAltName = DNS:<name>,DNS:*.<name>
1.3.6.1.4.1.54392.5.1620 = DER:<urkel hex>
1.3.6.1.4.1.54392.5.1621 = DER:<dnssec hex>
```

`openssl req -x509 -new -key key.pem -out cert.pem -days <n> -subj /CN=<name> -config <file> -extensions ext`

Keep the **same key**: the TLSA `3 1 1` record pins the key, so DNS never
changes. EC P-256 is fine: the htools generator only makes RSA keys, but SANE
and Dit verify the certificate with standard X.509 code, so any key the TLSA
record pins works.

**Wildcards:** the DNSSEC chain covers one name's `_443._tcp` TLSA record.
A certificate for `name` and `*.name` should embed the chain for `name`; other
subdomains would need their own certificate and chain. Decide whether to
limit Stateless DANE to the main name at first.

## Refresh

Proofs are tied to a tree root, which changes every 36 blocks (~6 h), and
clients only accept roots from the last ~1–2 weeks. So:

- Reissue **once a day** (e.g. a timer in `server.js`), fetching fresh proofs.
- Reuse Castell's existing renewal path (`renewCert` in `server.js`: new
  `certFile` name each time so Caddy reloads, same key).
- If fetching proofs fails, **keep the current certificate** and retry later;
  never replace a working certificate with one without proofs because of a
  network error. Show the state per site (proofs age, last error).
- Certificate validity can stay long (DANE-EE ignores dates), but a shorter
  one (e.g. 30 days) makes stale proofs obvious. Owner's call.

## Suggested UI (Castell's site page)

- A per-site toggle "Stateless DANE proofs (beta)", off by default.
- Status: proofs included yes/no, tree root age, last refresh, service used,
  last error.
- A note: only Stateless DANE clients read the proofs; browsers are unaffected.

## How to verify

- Inspect a generated certificate: `openssl x509 -in cert.pem -noout -text`
  should list both OIDs; `openssl asn1parse` shows the octet strings.
- Check that the embedded blobs equal what the service returned.
- **Dit's checker** already verifies these exact blobs (Dit repo, v0.5.0):
  `docker/dane/urkel.go` (Urkel proof, port of handshake-org/urkel, MIT),
  `docker/dane/hns.go` (name state, DS records), `docker/dane/dnssecchain.go`
  (chain anchored only on the on-chain DS), `docker/dane/check.go`
  (`dit-dane check -name <name> -urkel-file <hex> -dnssec-file <hex>` reads
  the blobs from files: useful to test what Castell embeds).
  Real test data: `docker/dane/testdata/nathan.woodburn.{urkel,dnssec}.hex`.
- SANE (randomlogin/sane) is the only existing client that reads proofs from
  certificates; its two reference sites (htools/, test.lazydane/) currently
  fail every TLS handshake, so a Castell site would be a useful live example.

## Done when

1. A Castell site can be switched to include the proofs; its certificate has
   both extensions with current blobs and is still pinned by the same TLSA.
2. Proofs refresh daily; failures keep the old certificate and show an error.
3. Tests cover building the openssl config, the refresh decision (fresh,
   failed, no TLSA) and that plain-DANE behaviour is unchanged when off.
4. Verified end to end: Dit's `dit-dane check` with `-urkel-file`/`-dnssec-file`
   on the blobs extracted from a real Castell certificate passes all steps.

Follow-up on the Dit side (not in Castell): Dit's "phase 2", reading the
proofs from a site's certificate inside the DANE proxy, becomes testable
once a Castell site serves them.
