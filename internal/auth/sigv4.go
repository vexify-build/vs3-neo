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

// Package auth implements AWS Signature Version 4 request signing used by
// S3, supporting both header-based (Authorization) and query-based
// (presigned URL) authentication.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	algorithm = "AWS4-HMAC-SHA256"
	service   = "s3"
	// unsignedPayload is used when a request body hash is unavailable or the
	// client used the S3 "unsigned payload" mode (typical for presigned URLs).
	unsignedPayload = "UNSIGNED-PAYLOAD"
)

// ErrNoAuth is returned when the request carries no signature.
var ErrNoAuth = errors.New("no authentication provided")

// Credential identifies an authenticated caller.
type Credential struct {
	AccessKey string
}

// Provider resolves the secret key for an access key.
type Provider interface {
	SecretKey(accessKey string) (string, bool)
}

// Verifier validates SigV4-signed requests against a Provider.
type Verifier struct {
	Provider Provider
	// Clock is used for presigned URL expiration checks (tests override it).
	Clock func() time.Time
	// AllowAnonymous permits unsigned requests.
	AllowAnonymous bool
}

// NewVerifier returns a Verifier for p.
func NewVerifier(p Provider) *Verifier {
	return &Verifier{Provider: p, Clock: time.Now}
}

// Verify checks the request's SigV4 signature. It returns the caller
// credential and whether the request was signed or anonymous.
func (v *Verifier) Verify(r *http.Request) (Credential, bool, error) {
	authz := r.Header.Get("Authorization")
	if strings.HasPrefix(authz, algorithm+" ") {
		cred, err := v.verifyHeader(r, authz)
		return cred, true, err
	}
	// Query-based auth (presigned URL).
	if r.URL.Query().Get("X-Amz-Algorithm") == algorithm {
		cred, err := v.verifyQuery(r)
		return cred, true, err
	}
	if v.AllowAnonymous {
		return Credential{}, false, nil
	}
	return Credential{}, false, ErrNoAuth
}

// ---- header-based auth ----

type authParts struct {
	accessKey     string
	date          string
	region        string
	service       string
	signedHeaders []string
	signature     string
}

func parseAuthHeader(authz string) (*authParts, error) {
	// "AWS4-HMAC-SHA256 Credential=AK/date/region/s3/aws4_request, SignedHeaders=..., Signature=..."
	body := strings.TrimPrefix(authz, algorithm+" ")
	parts := map[string]string{}
	for _, kv := range strings.Split(body, ",") {
		kv = strings.TrimSpace(kv)
		idx := strings.Index(kv, "=")
		if idx < 0 {
			continue
		}
		parts[strings.TrimSpace(kv[:idx])] = strings.TrimSpace(kv[idx+1:])
	}
	cred := parts["Credential"]
	credParts := strings.Split(cred, "/")
	if len(credParts) != 5 || credParts[4] != "aws4_request" {
		return nil, errors.New("auth: malformed credential scope")
	}
	ap := &authParts{
		accessKey: credParts[0],
		date:      credParts[1],
		region:    credParts[2],
		service:   credParts[3],
		signature: parts["Signature"],
	}
	if sh := parts["SignedHeaders"]; sh != "" {
		ap.signedHeaders = strings.Split(sh, ";")
	}
	return ap, nil
}

func (v *Verifier) verifyHeader(r *http.Request, authz string) (Credential, error) {
	ap, err := parseAuthHeader(authz)
	if err != nil {
		return Credential{}, err
	}
	if ap.service != service {
		return Credential{}, fmt.Errorf("auth: unsupported service %q", ap.service)
	}
	secret, ok := v.Provider.SecretKey(ap.accessKey)
	if !ok {
		return Credential{}, errors.New("auth: unknown access key")
	}
	amzDate := r.Header.Get("x-amz-date")
	if amzDate == "" {
		amzDate = ap.date + "T000000Z"
	}
	canonReq := buildCanonicalRequest(r, ap.signedHeaders, headerPayloadHash(r))
	stringToSign := buildStringToSign(amzDate, ap.date, ap.region, canonReq)
	signingKey := signingKey(secret, ap.date, ap.region)
	expected := hmacHex(signingKey, stringToSign)
	if !hmac.Equal([]byte(expected), []byte(ap.signature)) {
		return Credential{}, errors.New("auth: signature mismatch")
	}
	return Credential{AccessKey: ap.accessKey}, nil
}

func headerPayloadHash(r *http.Request) string {
	if h := r.Header.Get("x-amz-content-sha256"); h != "" {
		return h
	}
	return unsignedPayload
}

// ---- query-based (presigned) auth ----

func (v *Verifier) verifyQuery(r *http.Request) (Credential, error) {
	q := r.URL.Query()
	cred := q.Get("X-Amz-Credential")
	credParts := strings.Split(cred, "/")
	if len(credParts) != 5 || credParts[4] != "aws4_request" {
		return Credential{}, errors.New("auth: malformed presigned credential")
	}
	accessKey, date, region, svc := credParts[0], credParts[1], credParts[2], credParts[3]
	if svc != service {
		return Credential{}, fmt.Errorf("auth: unsupported service %q", svc)
	}
	expiresStr := q.Get("X-Amz-Expires")
	var expires time.Duration
	if expiresStr != "" {
		var secs int64
		if _, err := fmt.Sscanf(expiresStr, "%d", &secs); err != nil {
			return Credential{}, errors.New("auth: bad X-Amz-Expires")
		}
		expires = time.Duration(secs) * time.Second
	}
	amzDate, err := time.Parse("20060102T150405Z", q.Get("X-Amz-Date"))
	if err != nil {
		return Credential{}, errors.New("auth: bad X-Amz-Date")
	}
	now := time.Now()
	if v.Clock != nil {
		now = v.Clock()
	}
	if now.After(amzDate.Add(expires)) {
		return Credential{}, errors.New("auth: presigned URL expired")
	}
	if now.Before(amzDate.Add(-15 * time.Minute)) {
		return Credential{}, errors.New("auth: presigned URL too far in the future")
	}
	secret, ok := v.Provider.SecretKey(accessKey)
	if !ok {
		return Credential{}, errors.New("auth: unknown access key")
	}
	signedHeaders := []string{}
	if sh := q.Get("X-Amz-SignedHeaders"); sh != "" {
		signedHeaders = strings.Split(sh, ";")
	}
	canonReq := buildCanonicalRequest(r, signedHeaders, unsignedPayload)
	stringToSign := buildStringToSign(q.Get("X-Amz-Date"), date, region, canonReq)
	key := signingKey(secret, date, region)
	expected := hmacHex(key, stringToSign)
	if !hmac.Equal([]byte(expected), []byte(q.Get("X-Amz-Signature"))) {
		return Credential{}, errors.New("auth: signature mismatch")
	}
	return Credential{AccessKey: accessKey}, nil
}

// ---- canonical request construction ----

// buildCanonicalRequest assembles the AWS SigV4 canonical request. For query
// auth the X-Amz-Signature parameter is excluded, as required by AWS.
func buildCanonicalRequest(r *http.Request, signedHeaders []string, payloadHash string) string {
	method := r.Method
	canonicalURI := canonicalURI(r.URL)
	canonicalQuery := canonicalQueryString(r.URL, isQueryAuth(r))
	canonicalHeaders, headersList := canonicalHeadersString(r, signedHeaders)
	canonical := strings.Join([]string{
		method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		headersList,
		payloadHash,
	}, "\n")
	return canonical
}

func isQueryAuth(r *http.Request) bool {
	return r.URL.Query().Get("X-Amz-Algorithm") == algorithm
}

// canonicalURI returns the URI-encoded path as sent by the client (S3 does
// not double-encode, so the client's own encoding is the canonical form).
func canonicalURI(u *url.URL) string {
	p := u.EscapedPath()
	if p == "" {
		return "/"
	}
	return p
}

// canonicalQueryString sorts raw query pairs (excluding X-Amz-Signature for
// query auth) and joins them as name=value.
func canonicalQueryString(u *url.URL, excludeSignature bool) string {
	raw := u.RawQuery
	if raw == "" {
		return ""
	}
	type kv struct{ k, v string }
	var pairs []kv
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		idx := strings.Index(pair, "=")
		var k, v string
		if idx < 0 {
			k, v = pair, ""
		} else {
			k, v = pair[:idx], pair[idx+1:]
		}
		if excludeSignature && k == "X-Amz-Signature" {
			continue
		}
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	var sb strings.Builder
	for i, p := range pairs {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(p.k)
		sb.WriteByte('=')
		sb.WriteString(p.v)
	}
	return sb.String()
}

// canonicalHeadersString builds the sorted header block and the signed
// headers list (already sorted).
func canonicalHeadersString(r *http.Request, signedHeaders []string) (headersBlock, list string) {
	names := make([]string, len(signedHeaders))
	copy(names, signedHeaders)
	sort.Strings(names)

	// Lower-case + trim, preserving original header order from the request.
	values := map[string][]string{}
	for name := range r.Header {
		values[strings.ToLower(name)] = r.Header.Values(name)
	}
	// x-amz-date is often absent from header list but present in request.
	lowerHeaders := []string{}
	for _, n := range names {
		l := strings.ToLower(strings.TrimSpace(n))
		lowerHeaders = append(lowerHeaders, l)
	}
	var sb strings.Builder
	for _, name := range lowerHeaders {
		vs := values[name]
		if len(vs) == 0 {
			continue
		}
		val := strings.Join(vs, ",")
		// Collapse sequential spaces, per AWS spec.
		val = collapseSpaces(val)
		sb.WriteString(name)
		sb.WriteByte(':')
		sb.WriteString(val)
		sb.WriteByte('\n')
	}
	return sb.String(), strings.Join(lowerHeaders, ";")
}

func collapseSpaces(s string) string {
	trimmed := strings.TrimSpace(s)
	parts := strings.Fields(trimmed)
	return strings.Join(parts, " ")
}

func buildStringToSign(amzDate, date, region, canonicalRequest string) string {
	h := sha256.Sum256([]byte(canonicalRequest))
	scope := date + "/" + region + "/" + service + "/aws4_request"
	return strings.Join([]string{
		algorithm,
		amzDate,
		scope,
		hex.EncodeToString(h[:]),
	}, "\n")
}

func signingKey(secret, date, region string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	return hmacSHA256(kService, "aws4_request")
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func hmacHex(key []byte, data string) string {
	return hex.EncodeToString(hmacSHA256(key, data))
}

// ---- Presigner (mint presigned URLs) ----

// Presigner creates SigV4 presigned URLs for any S3-style request.
type Presigner struct {
	AccessKey string
	SecretKey string
	Region    string
	// Clock for testing.
	Clock func() time.Time
}

// Presign returns a URL for method against `path` (e.g. "/bucket/key") with
// the given query parameters, valid for expires seconds.
func (p *Presigner) Presign(method, host, path string, query url.Values, expires int64) (string, error) {
	now := time.Now()
	if p.Clock != nil {
		now = p.Clock()
	}
	amzDate := now.UTC().Format("20060102T150405Z")
	date := amzDate[:8]
	scope := date + "/" + p.Region + "/" + service + "/aws4_request"

	if query == nil {
		query = url.Values{}
	}
	query.Set("X-Amz-Algorithm", algorithm)
	query.Set("X-Amz-Credential", p.AccessKey+"/"+scope)
	query.Set("X-Amz-Date", amzDate)
	query.Set("X-Amz-Expires", fmt.Sprintf("%d", expires))
	query.Set("X-Amz-SignedHeaders", "host")

	// Build canonical request excluding the signature itself.
	fakeURL := &url.URL{Path: path, RawQuery: query.Encode()}
	// canonical query: sort + encode with %20, exclude X-Amz-Signature.
	canonQuery := encodeSortedQuery(query)
	canonReq := strings.Join([]string{
		method,
		encodePath(path),
		canonQuery,
		"host:" + host + "\n",
		"host",
		unsignedPayload,
	}, "\n")
	stringToSign := buildStringToSign(amzDate, date, p.Region, canonReq)
	sig := hmacHex(signingKey(p.SecretKey, date, p.Region), stringToSign)
	query.Set("X-Amz-Signature", sig)

	u := url.URL{Scheme: "http", Host: host, Path: path, RawQuery: encodeSortedQuery(query)}
	return u.String(), nil
}

// encodeSortedQuery returns RFC3986-encoded query string sorted by key.
func encodeSortedQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for i, k := range keys {
		vals := q[k]
		sort.Strings(vals)
		for _, v := range vals {
			if sb.Len() > 0 {
				sb.WriteByte('&')
			}
			sb.WriteString(encodeComponent(k))
			sb.WriteByte('=')
			sb.WriteString(encodeComponent(v))
		}
		_ = i
	}
	return sb.String()
}

// encodeComponent percent-encodes per RFC3986 (space -> %20).
func encodeComponent(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// encodePath percent-encodes each path segment while preserving "/".
func encodePath(p string) string {
	segments := strings.Split(p, "/")
	for i, seg := range segments {
		if seg != "" {
			segments[i] = encodeComponent(seg)
		}
	}
	return strings.Join(segments, "/")
}
