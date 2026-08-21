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

// vs3-neo's user-defined function (UDF) system.
//
// A Function is any object with `name()` and `handle(ctx)`:
//   { name: () => 'foo', async handle(ctx) { ... } }
//
// Functions can be used in two ways:
//   1. As HOOKS: configured in config.functions.hooks (e.g. onPut, onGet),
//      invoked automatically around the corresponding S3 operations.
//   2. Directly: POST /__function/:name runs a function ad-hoc.
//
// The ctx (FunctionContext) exposes request/response details and lets a
// function short-circuit the request (set ctx.response) or inspect/modify
// it.

import { registerBackend } from '../storage/storage.js';

const registry = new Map();

export function registerFunction(fn) {
  if (!fn || typeof fn.name !== 'function' || typeof fn.handle !== 'function') {
    throw new Error('plugin: function must implement name() and handle(ctx)');
  }
  const name = fn.name();
  if (!name) throw new Error('plugin: function name() returned empty');
  if (registry.has(name)) throw new Error(`plugin: function "${name}" already registered`);
  registry.set(name, fn);
}

export function getFunction(name) {
  return registry.get(name) || null;
}

export function listFunctions() {
  return [...registry.keys()];
}

// FunctionContext passed to every function invocation.
export class FunctionContext {
  constructor({ operation, method, bucket, key, versionId, headers, query, req, res, storage }) {
    this.operation = operation; // e.g. 'PutObject'
    this.method = method; // e.g. 'PUT'
    this.bucket = bucket;
    this.key = key;
    this.versionId = versionId;
    this.headers = headers; // request headers (lowercased)
    this.query = query; // decoded query params
    this.req = req; // raw Node request
    this.res = res; // raw Node response
    this.storage = storage; // the active storage backend
    this.meta = {}; // arbitrary scratch space shared across hooks
    this.log = (msg) => {
      (this._logger || console.log)(`[fn] ${msg}`);
    };
    // If a function sets ctx.response, it short-circuits the S3 handler.
    this.response = null; // { status, headers, body }
  }
}

// Hooks pipeline: run all functions listed for a hook point (comma separated
// in config). A function may set ctx.response to short-circuit.
export async function runHooks(hooks, hook, ctx) {
  const names = (hooks && hooks[hook]) || '';
  if (!names) return;
  for (const name of names.split(',').map((s) => s.trim()).filter(Boolean)) {
    const fn = getFunction(name);
    if (!fn) continue;
    await fn.handle(ctx);
    if (ctx.response) return;
  }
}

// convenience: register a function from a plain object
export function defineFunction(name, handle) {
  registerFunction({ name: () => name, handle });
}

// Ensure storage backends can also be registered from plugins.
export { registerBackend };
