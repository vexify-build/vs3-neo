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

// A tiny S3-compatible client used by tests, examples and CLI tooling.
// Signing is done with SigV4 (header-based). Works against vs3-neo and any
// other S3-compatible endpoint.

import { signRequest } from './auth/sigv4.js';

export class S3Client {
  constructor({ endpoint = 'http://127.0.0.1:9000', accessKey, secretKey, region = 'us-east-1' } = {}) {
    this.endpoint = endpoint.replace(/\/$/, '');
    this.accessKey = accessKey;
    this.secretKey = secretKey;
    this.region = region;
  }

  // Low-level signed request.
  async request(method, path, { query = {}, headers = {}, body } = {}) {
    const url = new URL(this.endpoint + path);
    for (const [k, v] of Object.entries(query)) {
      // S3 subresources use empty values (e.g. ?location, ?versioning, ?uploads);
      // only skip genuinely absent parameters.
      if (v !== undefined && v !== null) url.searchParams.set(k, v);
    }
    // Build a request with a consistent host header.
    const u = url.toString();
    const parsed = new URL(u);
    const host = parsed.host;

    const finalHeaders = { ...headers, host };
    const bodyBuffer = body === undefined ? null : Buffer.isBuffer(body) ? body : Buffer.from(body);
    const signed = signRequest({
      method,
      host,
      path: parsed.pathname,
      query: Object.fromEntries(parsed.searchParams.entries()),
      headers: Object.fromEntries(
        Object.entries(finalHeaders).filter(([k]) => k.toLowerCase() !== 'host'),
      ),
      bodyHash: bodyBuffer ? cryptoHash(bodyBuffer) : undefined,
      accessKey: this.accessKey,
      secretKey: this.secretKey,
      region: this.region,
    });

    const reqHeaders = { ...finalHeaders, ...signed };
    delete reqHeaders.host;
    // Note: do NOT set Content-Length manually — undici computes it from the
    // Buffer body, and a manually-set header collides with the auto one when
    // running under a custom global dispatcher (e.g. a proxy preload).

    const res = await fetch(u, {
      method,
      headers: reqHeaders,
      body: bodyBuffer,
      redirect: 'manual',
    });
    const text = await res.text();
    return { status: res.status, headers: res.headers, text, ok: res.ok };
  }

  // ---- convenience operations ----
  async createBucket(name) {
    return this.request('PUT', `/${name}`);
  }
  async listBuckets() {
    return this.request('GET', '/');
  }
  async headBucket(name) {
    return this.request('HEAD', `/${name}`);
  }
  async deleteBucket(name) {
    return this.request('DELETE', `/${name}`);
  }
  async putObject(bucket, key, body, headers = {}) {
    return this.request('PUT', `/${bucket}/${key}`, { headers, body });
  }
  async getObject(bucket, key, query = {}) {
    return this.request('GET', `/${bucket}/${key}`, { query });
  }
  async headObject(bucket, key, query = {}) {
    return this.request('HEAD', `/${bucket}/${key}`, { query });
  }
  async deleteObject(bucket, key, query = {}) {
    return this.request('DELETE', `/${bucket}/${key}`, { query });
  }
  async listObjects(bucket, query = {}) {
    return this.request('GET', `/${bucket}`, { query });
  }
  async listObjectsV2(bucket, query = {}) {
    return this.request('GET', `/${bucket}`, { query: { 'list-type': '2', ...query } });
  }
  async setVersioning(bucket, status) {
    const body = `<?xml version="1.0" encoding="UTF-8"?><VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>${status}</Status></VersioningConfiguration>`;
    return this.request('PUT', `/${bucket}`, { query: { versioning: '' }, headers: { 'Content-Type': 'application/xml' }, body });
  }
  async getVersioning(bucket) {
    return this.request('GET', `/${bucket}`, { query: { versioning: '' } });
  }
}

function cryptoHash(buf) {
  // hex sha256 of body for the x-amz-content-sha256 header
  return requireSha256(buf);
}

import crypto from 'node:crypto';
function requireSha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}
