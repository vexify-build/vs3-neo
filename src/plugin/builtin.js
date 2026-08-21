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

import { defineFunction } from './index.js';

// ---- built-in example functions ----

// "log": prints a one-line summary of every hooked operation.
defineFunction('log', async (ctx) => {
  ctx.log(
    `${ctx.operation} ${ctx.method} ${ctx.bucket}/${ctx.key} q=${JSON.stringify(ctx.query)}`,
  );
});

// "echo": returns a JSON summary of the request context (handy to test the
// UDF system). Invoke directly: POST /__function/echo
defineFunction('echo', async (ctx) => {
  ctx.response = {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(
      {
        operation: ctx.operation,
        method: ctx.method,
        bucket: ctx.bucket,
        key: ctx.key,
        versionId: ctx.versionId,
        query: ctx.query,
        headers: ctx.headers,
        time: new Date().toISOString(),
      },
      null,
      2,
    ),
  };
});

// "transform-upper": a PUT hook that uppercases the request body in place.
// Wire it via config.functions.hooks.onPut = "log,transform-upper".
// NOTE: transform must be the LAST hook in the list because it replaces the
// request body stream consumed by the S3 handler.
const transformUpperSymbol = Symbol('transformUpper');

function wrapUpper(stream) {
  let src = stream;
  return {
    ...src,
    pipe(dest) {
      return src.pipe(dest);
    },
    on(...args) {
      return src.on(...args);
    },
    [Symbol.asyncIterator]() {
      return (async function* () {
        for await (const chunk of src) {
          yield Buffer.from(String(chunk).toUpperCase());
        }
      })();
    },
  };
}

defineFunction('transform-upper', async (ctx) => {
  if (ctx.req && ctx.req.body) {
    ctx.req.body = wrapUpper(ctx.req.body);
    ctx.meta[transformUpperSymbol] = true;
  }
});

// "counter": per-key in-memory access counter. Adds x-vs3-counter response
// header on reads. Also demonstrates maintaining state inside a function.
const counters = new Map();

defineFunction('counter', async (ctx) => {
  if (ctx.res && !ctx.res.headersSent) {
    const k = `${ctx.bucket}/${ctx.key}`;
    const n = (counters.get(k) || 0) + 1;
    counters.set(k, n);
    ctx.res.setHeader('x-vs3-counter', String(n));
  }
});

// "deny": example of a policy-like hook that rejects an operation.
// Wire it via hooks.onDelete = "deny" to forbid deletions, for example.
defineFunction('deny', async (ctx) => {
  ctx.response = {
    status: 403,
    headers: { 'Content-Type': 'application/xml' },
    body: `<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>AccessDenied</Code><Message>Blocked by user-defined function "${ctx.operation}"</Message></Error>`,
  };
});

export { wrapUpper };
