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

// S3 XML namespace.
export const S3_NS = 'http://s3.amazonaws.com/doc/2006-03-01/';

// Escape XML text content.
export function esc(s) {
  if (s === undefined || s === null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Escape XML attribute values (quote-escaped only).
export function escAttr(s) {
  return esc(s);
}

// ISO8601 with milliseconds (S3 ListBuckets style).
export function iso8601(d = new Date()) {
  const dt = d instanceof Date ? d : new Date(d);
  return dt.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

// RFC1123 date for HTTP headers (Last-Modified, Date).
export function httpDate(d = new Date()) {
  return d.toUTCString();
}

// Build an XML document with a namespace root.
export function xmlDoc(rootTag, inner) {
  return `<?xml version="1.0" encoding="UTF-8"?>\n<${rootTag} xmlns="${S3_NS}">${inner}</${rootTag}>`;
}

// Simple element helper (escapes content).
export function el(tag, value, attrs = {}) {
  const a = Object.entries(attrs)
    .map(([k, v]) => ` ${k}="${escAttr(v)}"`)
    .join('');
  return `<${tag}${a}>${esc(value)}</${tag}>`;
}

// Element whose content is already-escaped XML (e.g. nested elements built by
// el()/rawEl()). Content is inserted verbatim without escaping.
export function rawEl(tag, value, attrs = {}) {
  const a = Object.entries(attrs)
    .map(([k, v]) => ` ${k}="${escAttr(v)}"`)
    .join('');
  return `<${tag}${a}>${value === undefined || value === null ? '' : value}</${tag}>`;
}

// Boolean element (S3 renders "true"/"false").
export function boolEl(tag, value) {
  return el(tag, value ? 'true' : 'false');
}

// ISO timestamp element.
export function timeEl(tag, date) {
  return el(tag, iso8601(date));
}
