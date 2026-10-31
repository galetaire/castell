'use strict';

const {execFile} = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const {promisify} = require('util');
const {UserError} = require('./errors');

const run = promisify(execFile);
const OPENSSL = process.env.LLAR_OPENSSL || 'openssl';
// Git Bash's openssl on Windows rewrites "/CN=..." into a file path; harmless elsewhere.
const env = {...process.env, MSYS_NO_PATHCONV: '1'};
const CERT_DAYS = 3650;

async function openssl(args) {
  try {
    await run(OPENSSL, args, {env});
  } catch (e) {
    throw new Error(`openssl failed: ${(e.stderr || e.message).trim()}`);
  }
}

async function generateKey(keyFile) {
  await openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', keyFile]);
  fs.chmodSync(keyFile, 0o600);
}

// Self-signed, valid for 10 years, for the name and its subdomains. DANE (3 1 1)
// pins the public key, so issuing a new certificate from the same key keeps the TLSA record valid.
async function issueCert(name, keyFile, certFile) {
  await openssl([
    'req', '-x509', '-new', '-key', keyFile, '-out', certFile, '-days', String(CERT_DAYS),
    '-subj', `/CN=${name}`, '-addext', `subjectAltName=DNS:${name},DNS:*.${name}`,
  ]);
}

// An existing key, e.g. from a site hosted elsewhere, so its TLSA record stays the same.
function normalizeKey(pem) {
  let key;
  try {
    key = crypto.createPrivateKey(String(pem));
  } catch (e) {
    throw new UserError('That file is not a readable private key (PEM). Password-protected keys are not supported.');
  }
  if (!['ec', 'rsa'].includes(key.asymmetricKeyType)) {
    throw new UserError(`Llar supports EC and RSA keys; this one is ${key.asymmetricKeyType}.`);
  }
  return key.export({type: 'pkcs8', format: 'pem'});
}

const sha256 = data => crypto.createHash('sha256').update(data).digest('hex');
const spkiHash = publicKey => sha256(publicKey.export({type: 'spki', format: 'der'}));

// The "3 1 1" TLSA value: SHA-256 of the public key (SubjectPublicKeyInfo).
const tlsaFromKeyFile = keyFile => spkiHash(crypto.createPublicKey(fs.readFileSync(keyFile)));
const tlsaFromCert = x509 => spkiHash(x509.publicKey);

function certInfo(certFile) {
  const cert = new crypto.X509Certificate(fs.readFileSync(certFile));
  return {validFrom: new Date(cert.validFrom).toISOString(), validTo: new Date(cert.validTo).toISOString()};
}

module.exports = {generateKey, issueCert, normalizeKey, tlsaFromKeyFile, tlsaFromCert, certInfo};
