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

import fs from 'node:fs/promises';
import path from 'node:path';

import { Storage, registerBackend } from './storage.js';
import { DiskStorage } from './disk.js';

// Example of a CUSTOM storage backend plugged in through the registry.
//
// "custom-mirror" delegates all operations to the disk backend (so data is
// durable) and additionally appends every mutation to an append-only audit
// log (audit.jsonl). This demonstrates how easy it is to add behaviour
// around the Storage interface without touching the core server.
export class MirrorStorage extends Storage {
  get name() {
    return 'custom-mirror';
  }

  constructor(inner, auditPath) {
    super();
    this.inner = inner;
    this.auditPath = auditPath;
  }

  async init() {
    await this.inner.init();
    await fs.mkdir(path.dirname(this.auditPath), { recursive: true });
  }

  async _audit(op, detail = {}) {
    const line = JSON.stringify({ t: new Date().toISOString(), op, ...detail }) + '\n';
    await fs.appendFile(this.auditPath, line, 'utf8');
  }

  // ---- buckets ----
  async createBucket(bucket) {
    await this.inner.createBucket(bucket);
    await this._audit('createBucket', { bucket });
  }
  async deleteBucket(bucket) {
    await this.inner.deleteBucket(bucket);
    await this._audit('deleteBucket', { bucket });
  }
  async listBuckets() {
    return this.inner.listBuckets();
  }
  async bucketExists(bucket) {
    return this.inner.bucketExists(bucket);
  }
  async getVersioning(bucket) {
    return this.inner.getVersioning(bucket);
  }
  async setVersioning(bucket, status) {
    await this.inner.setVersioning(bucket, status);
    await this._audit('setVersioning', { bucket, status });
  }

  // ---- objects ----
  async putObject(bucket, key, stream, size, opts) {
    const info = await this.inner.putObject(bucket, key, stream, size, opts);
    await this._audit('putObject', { bucket, key, size: info.size, etag: info.etag, versionId: info.versionId });
    return info;
  }
  async getObject(bucket, key, versionId, range) {
    return this.inner.getObject(bucket, key, versionId, range);
  }
  async headObject(bucket, key, versionId) {
    return this.inner.headObject(bucket, key, versionId);
  }
  async deleteObject(bucket, key, versionId) {
    const info = await this.inner.deleteObject(bucket, key, versionId);
    await this._audit('deleteObject', { bucket, key, versionId, deleted: !!info });
    return info;
  }
  async copyObject(srcBucket, srcKey, dstBucket, dstKey, opts) {
    const res = await this.inner.copyObject(srcBucket, srcKey, dstBucket, dstKey, opts);
    await this._audit('copyObject', { srcBucket, srcKey, dstBucket, dstKey });
    return res;
  }
  async listObjects(bucket, params) {
    return this.inner.listObjects(bucket, params);
  }
  async listObjectVersions(bucket, params) {
    return this.inner.listObjectVersions(bucket, params);
  }

  // ---- multipart ----
  async createMultipartUpload(bucket, key, opts) {
    const id = await this.inner.createMultipartUpload(bucket, key, opts);
    await this._audit('createMultipartUpload', { bucket, key, uploadId: id });
    return id;
  }
  async uploadPart(bucket, key, uploadId, partNumber, stream, size) {
    return this.inner.uploadPart(bucket, key, uploadId, partNumber, stream, size);
  }
  async completeMultipartUpload(bucket, key, uploadId, parts) {
    const info = await this.inner.completeMultipartUpload(bucket, key, uploadId, parts);
    await this._audit('completeMultipartUpload', { bucket, key, uploadId, etag: info.etag });
    return info;
  }
  async abortMultipartUpload(bucket, key, uploadId) {
    await this.inner.abortMultipartUpload(bucket, key, uploadId);
    await this._audit('abortMultipartUpload', { bucket, key, uploadId });
  }
  async listParts(bucket, key, uploadId) {
    return this.inner.listParts(bucket, key, uploadId);
  }
  async listMultipartUploads(bucket) {
    return this.inner.listMultipartUploads(bucket);
  }
}

// The factory receives the storage config map, letting users wire custom
// backends (and their own options) from configuration.
registerBackend('custom-mirror', (cfg = {}) => {
  const inner = new DiskStorage(cfg.dataDir || './data');
  const auditPath = cfg.auditPath || path.join(cfg.dataDir || './data', 'audit.jsonl');
  return new MirrorStorage(inner, auditPath);
});
