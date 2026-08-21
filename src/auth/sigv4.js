// Copyright 2026 vs3-neo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import crypto from 'node:crypto';

export const ALGORITHM = 'AWS4-HMAC-SHA256';
export const SERVICE = 's3';
const UNSIGNED_PAYLOAD = 'UNSIGNED-PAYLOAD';

// S3-compatible error codes for auth failures.
export class AuthError extends Error {
  constructor(code, message, status = 403) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

const sigMismatch = () =>
  new AuthError('SignatureDoesNotMatch', 'The request signature we calculated does not match the signature you provided.');
const noAuth = () => new AuthError('AccessDenied', 'Access Denied. No credentials provided.', 403);
const expired = () => new AuthError('AccessDenied', 'Request has expired', 403);

function hmac(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest();
}

function sha256hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// Parse AWS SigV4 basic date "YYYYMMDDTHHMMSSZ" into a Date. This is not the
// ISO8601 form that `new Date()` accepts, so it must be parsed manually.
export function parseAmzDate(s) {
  const m = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/.exec(s || '');
  if (!m) return new Date(NaN);
  return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
}

function hex(buf) {
  return buf.toString('hex');
}

function signingKey(secret, date, region) {
  const kDate = hmac('AWS4' + secret, date);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, SERVICE);
  return hmac(kService, 'aws4_request');
}

// ---- canonical request helpers ----

// RFC3986 percent-encode (space -> %20).
function enc(s) {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

function canonicalURI(rawPath) {
  if (!rawPath || rawPath === '') return '/';
  return rawPath
    .split('/')
    .map((seg) => (seg === '' ? '' : enc(seg)))
    .join('/');
}

// canonicalQueryString sorts raw name=value pairs. For presigned (query) auth
// the X-Amz-Signature parameter is excluded.
function canonicalQueryString(queryParts, excludeSignature) {
  let pairs = queryParts.filter((p) => p.name !== '');
  if (excludeSignature) {
    pairs = pairs.filter((p) => p.name !== 'X-Amz-Signature');
  }
  pairs.sort((a, b) => (a.name + '\u0000' + a.value).localeCompare(b.name + '\u0000' + b.value));
  return pairs.map((p) => `${p.name}=${p.value}`).join('&');
}

// Parse raw query string into {name, value} pairs preserving original encoding.
function parseQuery(rawQuery) {
  if (!rawQuery) return [];
  const pairs = [];
  for (const pair of rawQuery.split('&')) {
    if (pair === '') continue;
    const idx = pair.indexOf('=');
    if (idx < 0) pairs.push({ name: pair, value: '' });
    else pairs.push({ name: pair.slice(0, idx), value: pair.slice(idx + 1) });
  }
  return pairs;
}

// Build canonical headers block. headers is the lowercased map from Node.
function canonicalHeaders(headers, signedHeaders) {
  const sorted = signedHeaders.slice().sort();
  const lines = [];
  const list = [];
  for (const name of sorted) {
    const value = headers[name];
    if (value === undefined) continue;
    // Multi-value headers are comma-joined; collapse whitespace per AWS.
    const joined = (Array.isArray(value) ? value : [value])
      .map((v) => String(v).trim().replace(/\s+/g, ' '))
      .join(',');
    lines.push(`${name}:${joined}\n`);
    list.push(name);
  }
  return { block: lines.join(''), list: list.join(';') };
}

function buildStringToSign(amzDate, scope, canonicalRequest) {
  return [
    ALGORITHM,
    amzDate,
    scope,
    sha256hex(canonicalRequest),
  ].join('\n');
}

function buildCanonicalRequest(req, method, queryParts, signedHeaders, payloadHash) {
  const { block, list } = canonicalHeaders(req.headers, signedHeaders);
  const canonical = [
    method,
    canonicalURI(req.path),
    canonicalQueryString(queryParts, req.isQueryAuth),
    block,
    list,
    payloadHash,
  ].join('\n');
  return canonical;
}

// ---- request verification ----

function headerPayloadHash(req) {
  const v = req.headers['x-amz-content-sha256'];
  return v || UNSIGNED_PAYLOAD;
}

function parseAuthHeader(authz) {
  const body = authz.slice(ALGORITHM.length + 1);
  const parts = {};
  for (const kv of body.split(',')) {
    const idx = kv.indexOf('=');
    if (idx < 0) continue;
    parts[kv.slice(0, idx).trim()] = kv.slice(idx + 1).trim();
  }
  const credParts = (parts.Credential || '').split('/');
  if (credParts.length !== 5 || credParts[4] !== 'aws4_request') {
    throw new AuthError('AuthorizationHeaderMalformed', 'The authorization header is malformed.', 400);
  }
  return {
    accessKey: credParts[0],
    date: credParts[1],
    region: credParts[2],
    service: credParts[3],
    signedHeaders: parts.SignedHeaders ? parts.SignedHeaders.split(';') : [],
    signature: parts.Signature || '',
  };
}

function verifyHeaderAuth(req, provider) {
  const ap = parseAuthHeader(req.headers.authorization);
  if (ap.service !== SERVICE) {
    throw new AuthError('AuthorizationHeaderMalformed', `Unsupported service ${ap.service}`, 400);
  }
  const secret = provider.secretKey(ap.accessKey);
  if (!secret) throw new AuthError('InvalidAccessKeyId', 'The AWS Access Key Id you provided does not exist in our records.');
  const amzDate = req.headers['x-amz-date'] || `${ap.date}T000000Z`;
  const canonical = buildCanonicalRequest(req, req.method, req.queryParts, ap.signedHeaders, headerPayloadHash(req));
  const scope = `${ap.date}/${ap.region}/${SERVICE}/aws4_request`;
  const sts = buildStringToSign(amzDate, scope, canonical);
  const expected = hex(hmac(signingKey(secret, ap.date, ap.region), sts));
  if (!timingSafeEqualHex(expected, ap.signature)) throw sigMismatch();
  return ap.accessKey;
}

function verifyQueryAuth(req, provider, clock) {
  const q = req.queryParams; // decoded params
  const credParts = (q['X-Amz-Credential'] || '').split('/');
  if (credParts.length !== 5 || credParts[4] !== 'aws4_request') {
    throw new AuthError('AuthorizationQueryParametersError', 'Query-string authentication version 4 requires the X-Amz-Algorithm, X-Amz-Credential, X-Amz-Signature, X-Amz-Date, X-Amz-SignedHeaders, and X-Amz-Expires parameters.', 400);
  }
  const [accessKey, date, region, service] = credParts;
  if (service !== SERVICE) {
    throw new AuthError('AuthorizationQueryParametersError', `Unsupported service ${service}`, 400);
  }
  const expires = parseInt(q['X-Amz-Expires'] || '0', 10);
  const amzDate = parseAmzDate(q['X-Amz-Date']);
  const now = clock ? clock() : new Date();
  if (Number.isNaN(amzDate.getTime())) {
    throw new AuthError('AccessDenied', 'Invalid date in query string', 403);
  }
  if (now.getTime() > amzDate.getTime() + expires * 1000) throw expired();
  const secret = provider.secretKey(accessKey);
  if (!secret) throw new AuthError('InvalidAccessKeyId', 'The AWS Access Key Id you provided does not exist in our records.');
  const signedHeaders = (q['X-Amz-SignedHeaders'] || '').split(';').filter(Boolean);
  const canonical = buildCanonicalRequest(req, req.method, req.queryParts, signedHeaders, UNSIGNED_PAYLOAD);
  const scope = `${date}/${region}/${SERVICE}/aws4_request`;
  const sts = buildStringToSign(q['X-Amz-Date'], scope, canonical);
  const expected = hex(hmac(signingKey(secret, date, region), sts));
  if (!timingSafeEqualHex(expected, q['X-Amz-Signature'] || '')) throw sigMismatch();
  return accessKey;
}

function timingSafeEqualHex(a, b) {
  const ab = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

// ---- public verifier ----

// req is a normalized request object:
//   { method, path, rawQuery, queryParts, queryParams, headers, isQueryAuth }
// provider: { secretKey(accessKey) -> secret|undefined }
// opts: { anonymous, clock }
// Returns { accessKey, signed }.
export function verifyRequest(req, provider, opts = {}) {
  const authz = req.headers.authorization || '';
  if (authz.startsWith(ALGORITHM + ' ')) {
    const accessKey = verifyHeaderAuth(req, provider);
    return { accessKey, signed: true };
  }
  if (req.isQueryAuth) {
    const accessKey = verifyQueryAuth(req, provider, opts.clock);
    return { accessKey, signed: true };
  }
  if (opts.anonymous) return { accessKey: null, signed: false };
  throw noAuth();
}

// ---- Presigner (mint presigned URLs) ----

export class Presigner {
  constructor({ accessKey, secretKey, region = 'us-east-1', clock } = {}) {
    this.accessKey = accessKey;
    this.secretKey = secretKey;
    this.region = region;
    this.clock = clock;
  }

  // Presign returns a URL for method against `path` (e.g. "/bucket/key").
  // query is a plain object of extra params (encoded properly).
  presign(method, host, path, query = {}, expires = 3600) {
    const now = this.clock ? this.clock() : new Date();
    const amzDate = now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
    const date = amzDate.slice(0, 8);
    const scope = `${date}/${this.region}/${SERVICE}/aws4_request`;

    const params = { ...query };
    params['X-Amz-Algorithm'] = ALGORITHM;
    params['X-Amz-Credential'] = `${this.accessKey}/${scope}`;
    params['X-Amz-Date'] = amzDate;
    params['X-Amz-Expires'] = String(expires);
    params['X-Amz-SignedHeaders'] = 'host';

    const sortedKeys = Object.keys(params).sort();
    const canonicalQuery = sortedKeys
      .map((k) => `${enc(k)}=${enc(params[k])}`)
      .join('&');

    const canonical = [
      method,
      canonicalURI(path),
      canonicalQuery,
      `host:${host}\n`,
      'host',
      UNSIGNED_PAYLOAD,
    ].join('\n');
    const sts = buildStringToSign(amzDate, scope, canonical);
    const signature = hex(hmac(signingKey(this.secretKey, date, this.region), sts));

    const q = sortedKeys.map((k) => `${enc(k)}=${enc(params[k])}`).join('&');
    const qs = `${q}&X-Amz-Signature=${signature}`;
    return `http://${host}${path}?${qs}`;
  }
}

// ---- client-side signer (used by the Go/Node test clients & SDK parity) ----

// signHeaders returns the Authorization header for a normal (header-based)
// signed request.
export function signRequest({ method, host, path, query = {}, headers = {}, bodyHash, secretKey, accessKey, region = 'us-east-1', amzDate }) {
  const now = new Date();
  const ts = (amzDate || now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z'));
  const date = ts.slice(0, 8);
  const scope = `${date}/${region}/${SERVICE}/aws4_request`;
  const payloadHash = bodyHash || UNSIGNED_PAYLOAD;

  const signedHeaderNames = Object.keys(headers)
    .map((k) => k.toLowerCase())
    .sort();
  signedHeaderNames.push('host');
  const sortedUnique = [...new Set(signedHeaderNames)].sort();

  // Canonical headers from the provided set (plus host). Header names are
  // normalized to lowercase so lookups against the sorted signed list work
  // even when callers pass mixed-case names (e.g. "Content-Type").
  const allHeaders = { host };
  for (const [k, v] of Object.entries(headers)) {
    allHeaders[k.toLowerCase()] = v;
  }
  const lines = [];
  for (const name of sortedUnique) {
    const value = allHeaders[name];
    if (value === undefined) continue;
    lines.push(`${name}:${String(value).trim().replace(/\s+/g, ' ')}\n`);
  }
  const canonicalHeadersBlock = lines.join('');
  const signedHeadersList = sortedUnique.join(';');

  const queryPairs = Object.entries(query)
    .map(([k, v]) => ({ name: enc(k), value: enc(v) }))
    .sort((a, b) => (a.name + '\u0000' + a.value).localeCompare(b.name + '\u0000' + b.value));
  const canonicalQuery = queryPairs.map((p) => `${p.name}=${p.value}`).join('&');

  const canonical = [
    method,
    canonicalURI(path),
    canonicalQuery,
    canonicalHeadersBlock,
    signedHeadersList,
    payloadHash,
  ].join('\n');
  const sts = buildStringToSign(ts, scope, canonical);
  const signature = hex(hmac(signingKey(secretKey, date, region), sts));
  const authz = `${ALGORITHM} Credential=${accessKey}/${scope}, SignedHeaders=${signedHeadersList}, Signature=${signature}`;
  return { authorization: authz, 'x-amz-date': ts, 'x-amz-content-sha256': payloadHash };
}
