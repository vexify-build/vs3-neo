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

// Server-side encryption (SSE-S3, AES-256-GCM) helpers shared by the
// storage backends. A 32-byte master key is required; callers are
// responsible for persisting it (disk) or deriving it from config
// (memory). The plaintext MD5 is preserved as the object ETag, matching
// S3's behaviour where SSE does not change the ETag.

import crypto from 'node:crypto';
import fs from 'node:fs/promises';

export const SSE_HEADER = 'x-amz-server-side-encryption';
export const SSE_ALGORITHM = 'AES256';
const CIPHER = 'aes-256-gcm';
const IV_LEN = 12;

// Derive a stable 32-byte key from a configured secret (sha256), or
// generate a fresh random one (e.g. for the ephemeral memory backend).
export function deriveKey(secret) {
  if (secret) return crypto.createHash('sha256').update(String(secret)).digest();
  return crypto.randomBytes(32);
}

export function encryptBuffer(buf, key) {
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv(CIPHER, key, iv);
  const data = Buffer.concat([cipher.update(buf), cipher.final()]);
  return { data, nonce: iv.toString('hex'), tag: cipher.getAuthTag().toString('hex') };
}

export function decryptBuffer(buf, key, nonceHex, tagHex) {
  const decipher = crypto.createDecipheriv(CIPHER, key, Buffer.from(nonceHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return Buffer.concat([decipher.update(buf), decipher.final()]);
}

// Encrypt an entire file into `dest`, returning the GCM metadata.
export async function encryptFile(srcPath, destPath, key) {
  const data = await fs.readFile(srcPath);
  const { data: enc, nonce, tag } = encryptBuffer(data, key);
  await fs.writeFile(destPath, enc);
  return { nonce, tag };
}

// Decrypt a whole encrypted file into a Buffer.
export async function decryptFileToBuffer(srcPath, key, nonceHex, tagHex) {
  const data = await fs.readFile(srcPath);
  return decryptBuffer(data, key, nonceHex, tagHex);
}

// Persist/generate the master key file for the disk backend.
export async function ensureMasterKey(keyPath) {
  let key;
  try {
    const hex = (await fs.readFile(keyPath, 'utf8')).trim();
    key = Buffer.from(hex, 'hex');
  } catch {
    key = crypto.randomBytes(32);
    await fs.mkdir(keyPath.split('/').slice(0, -1).join('/'), { recursive: true });
    await fs.writeFile(keyPath, key.toString('hex'));
  }
  if (key.length !== 32) throw new Error('sse: master key must be 32 bytes');
  return key;
}
