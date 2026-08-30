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

// Minimal bucket-policy evaluator for the subset of IAM policy semantics
// vs3-neo supports:
//   - Effect: Allow | Deny
//   - Principal: "*", a plain access key, an ARN ending with the key, or a list
//   - Action: "*", "s3:*", exact action, or a pattern with leading/trailing "*"
//   - Resource: "*", "arn:aws:s3:::bucket", "arn:aws:s3:::bucket/*", or a list
//
// Evaluation order (matching AWS): an explicit Deny always wins, then an
// explicit Allow; if no statement matches, the request falls back to the
// identity-based decision (authenticated => allowed, anonymous => denied).

export function evaluatePolicy(policyDoc, { principal, action, resource }) {
  let policy;
  try {
    policy = typeof policyDoc === 'string' ? JSON.parse(policyDoc) : policyDoc;
  } catch {
    // A malformed policy must not silently grant access.
    return principal ? 'allow' : 'deny';
  }
  const raw = Array.isArray(policy.Statement) ? policy.Statement : policy.Statement ? [policy.Statement] : [];
  const statements = raw.filter(Boolean);
  if (statements.length === 0) return principal ? 'allow' : 'deny';

  let matchedAllow = false;
  for (const s of statements) {
    const effect = String(s.Effect || '').toLowerCase();
    if (effect !== 'allow' && effect !== 'deny') continue;
    const hit = stmtMatches(s, principal, action, resource);
    if (!hit) continue;
    if (effect === 'deny') return 'deny';
    matchedAllow = true;
  }
  if (matchedAllow) return 'allow';
  return principal ? 'allow' : 'deny';
}

function stmtMatches(s, principal, action, resource) {
  if (!matchPatterns(s.Principal, principal, matchPrincipal)) return false;
  if (!matchPatterns(s.Action, action, matchAction)) return false;
  if (!matchPatterns(s.Resource, resource, matchResource)) return false;
  return true;
}

function toList(v) {
  if (v === undefined || v === null) return null;
  return Array.isArray(v) ? v : [v];
}

// matcher(pattern, value) -> bool. Any pattern in the list matching wins.
function matchPatterns(patterns, value, matcher) {
  const list = toList(patterns);
  if (list === null) return false;
  if (value === undefined || value === null) return false;
  return list.some((p) => matcher(normalizePattern(p), value));
}

// Principal entries may use the object form { "AWS": "*" } / { "Service": ... }.
function normalizePattern(p) {
  if (p && typeof p === 'object' && !Array.isArray(p)) {
    if (p.AWS !== undefined) return p.AWS;
    if (p.Service !== undefined) return p.Service;
    return p;
  }
  return p;
}

function matchPrincipal(pattern, principal) {
  if (pattern === '*') return true;
  if (!principal) return false;
  const p = String(pattern);
  if (p === principal) return true;
  // ARN form: .../user/<key> or ...:user/<key>
  return p.split('/').pop() === principal || p.endsWith(':' + principal);
}

function matchAction(pattern, action) {
  const p = String(pattern).toLowerCase();
  const a = String(action).toLowerCase();
  if (p === '*') return true;
  if (p.endsWith('*')) return a.startsWith(p.slice(0, -1));
  return p === a;
}

function matchResource(pattern, resource) {
  const p = String(pattern);
  const r = String(resource);
  if (p === '*') return true;
  if (p.endsWith('*')) return r.startsWith(p.slice(0, -1));
  return p === r;
}
