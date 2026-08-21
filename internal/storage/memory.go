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

package storage

import (
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vs3-neo/vs3-neo/internal/model"
)

// Memory is an ephemeral Storage backend kept entirely in RAM. It is useful
// for tests, demos and as a reference implementation of the Storage
// interface.
type Memory struct {
	mu sync.RWMutex
	// buckets[name] -> versioning status
	buckets map[string]*memBucket
}

type memBucket struct {
	created    time.Time
	versioning string
	objects    map[string]*memObject // key -> logical object
	uploads    map[string]*memUpload // uploadID -> upload
}

type memVersion struct {
	info    model.ObjectInfo
	data    []byte
	deleted bool // delete marker
}

type memObject struct {
	versions []*memVersion // newest first
}

type memUpload struct {
	key         string
	contentType string
	userMeta    map[string]string
	initiated   time.Time
	parts       map[int]model.PartInfo
	partData    map[int][]byte
}

// NewMemory creates an empty in-memory backend.
func NewMemory() *Memory {
	return &Memory{buckets: map[string]*memBucket{}}
}

func (m *Memory) CreateBucket(ctx context.Context, bucket string) error {
	if err := ValidateBucketName(bucket); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.buckets[bucket]; ok {
		return ErrBucketAlreadyExists
	}
	m.buckets[bucket] = &memBucket{
		created: TSNow(),
		objects: map[string]*memObject{},
		uploads: map[string]*memUpload{},
	}
	return nil
}

func (m *Memory) DeleteBucket(ctx context.Context, bucket string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.buckets[bucket]
	if !ok {
		return ErrNoSuchBucket
	}
	if len(b.objects) > 0 || len(b.uploads) > 0 {
		return ErrBucketNotEmpty
	}
	delete(m.buckets, bucket)
	return nil
}

func (m *Memory) ListBuckets(ctx context.Context) ([]model.BucketInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.BucketInfo, 0, len(m.buckets))
	for name, b := range m.buckets {
		out = append(out, model.BucketInfo{Name: name, CreationDate: b.created})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) BucketExists(ctx context.Context, bucket string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.buckets[bucket]
	return ok, nil
}

func (m *Memory) GetVersioning(ctx context.Context, bucket string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.buckets[bucket]
	if !ok {
		return "", ErrNoSuchBucket
	}
	return b.versioning, nil
}

func (m *Memory) SetVersioning(ctx context.Context, bucket, status string) error {
	if status != "" && status != "Enabled" && status != "Suspended" {
		return fmt.Errorf("%w: invalid versioning status %q", ErrInvalidVersion, status)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.buckets[bucket]
	if !ok {
		return ErrNoSuchBucket
	}
	b.versioning = status
	return nil
}

func (m *Memory) PutObject(ctx context.Context, bucket, key string, r io.Reader, size int64, opts model.PutOptions) (model.ObjectInfo, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return model.ObjectInfo{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.buckets[bucket]
	if !ok {
		return model.ObjectInfo{}, ErrNoSuchBucket
	}
	versionID := "null"
	if b.versioning == "Enabled" {
		versionID = newVersionID()
	}
	etag := fmt.Sprintf("%x", md5.Sum(data))
	info := model.ObjectInfo{
		Bucket: bucket, Key: key, VersionID: versionID,
		Size: int64(len(data)), ETag: etag, ContentType: opts.ContentType,
		UserMetadata: opts.UserMetadata, LastModified: TSNow(), StorageClass: "STANDARD",
	}
	obj, ok := b.objects[key]
	if !ok {
		obj = &memObject{}
		b.objects[key] = obj
	}
	if b.versioning == "Enabled" {
		obj.versions = append([]*memVersion{{info: info, data: data}}, obj.versions...)
	} else {
		obj.versions = []*memVersion{{info: info, data: data}}
	}
	return info, nil
}

func (m *Memory) GetObject(ctx context.Context, bucket, key, versionID string, off, length int64) (GetObjectResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.buckets[bucket]
	if !ok {
		return GetObjectResult{}, ErrNoSuchBucket
	}
	obj, ok := b.objects[key]
	if !ok {
		return GetObjectResult{}, ErrNoSuchKey
	}
	v := m.findVersion(obj, versionID)
	if v == nil || v.deleted {
		return GetObjectResult{}, ErrNoSuchKey
	}
	var body []byte
	if off >= 0 {
		if off > int64(len(v.data)) {
			return GetObjectResult{}, ErrInvalidRange
		}
		body = v.data[off:]
		if length >= 0 && int64(len(body)) > length {
			body = body[:length]
		}
	} else {
		body = v.data
	}
	return GetObjectResult{Object: v.info, Body: io.NopCloser(bytes.NewReader(body))}, nil
}

func (m *Memory) HeadObject(ctx context.Context, bucket, key, versionID string) (model.ObjectInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.buckets[bucket]
	if !ok {
		return model.ObjectInfo{}, ErrNoSuchBucket
	}
	obj, ok := b.objects[key]
	if !ok {
		return model.ObjectInfo{}, ErrNoSuchKey
	}
	v := m.findVersion(obj, versionID)
	if v == nil || v.deleted {
		return model.ObjectInfo{}, ErrNoSuchKey
	}
	return v.info, nil
}

func (m *Memory) DeleteObject(ctx context.Context, bucket, key, versionID string) (model.ObjectInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.buckets[bucket]
	if !ok {
		return model.ObjectInfo{}, ErrNoSuchBucket
	}
	obj, ok := b.objects[key]
	if !ok {
		if b.versioning == "Enabled" {
			marker := model.ObjectInfo{
				Bucket: bucket, Key: key, VersionID: newVersionID(),
				IsDeleteMarker: true, LastModified: TSNow(),
			}
			b.objects[key] = &memObject{versions: []*memVersion{{info: marker, deleted: true}}}
			return marker, nil
		}
		return model.ObjectInfo{}, nil
	}
	if versionID != "" {
		for i, v := range obj.versions {
			if v.info.VersionID == versionID {
				if !v.deleted {
					obj.versions = append(obj.versions[:i], obj.versions[i+1:]...)
				} else {
					obj.versions = append(obj.versions[:i], obj.versions[i+1:]...)
				}
				if len(obj.versions) == 0 {
					delete(b.objects, key)
				}
				return v.info, nil
			}
		}
		return model.ObjectInfo{}, ErrNoSuchKey
	}
	if b.versioning == "Enabled" {
		marker := model.ObjectInfo{
			Bucket: bucket, Key: key, VersionID: newVersionID(),
			IsDeleteMarker: true, LastModified: TSNow(),
		}
		obj.versions = append([]*memVersion{{info: marker, deleted: true}}, obj.versions...)
		return marker, nil
	}
	latest := obj.versions[0]
	obj.versions = nil
	delete(b.objects, key)
	return latest.info, nil
}

func (m *Memory) CopyObject(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string, opts model.PutOptions) (model.CopyObjectResult, error) {
	src, err := m.GetObject(ctx, srcBucket, srcKey, "", -1, -1)
	if err != nil {
		return model.CopyObjectResult{}, err
	}
	defer src.Body.Close()
	info, err := m.PutObject(ctx, dstBucket, dstKey, src.Body, src.Object.Size, opts)
	if err != nil {
		return model.CopyObjectResult{}, err
	}
	return model.CopyObjectResult{ETag: info.ETag, LastModified: info.LastModified, Object: info}, nil
}

func (m *Memory) ListObjects(ctx context.Context, bucket, prefix, delimiter, marker string, maxKeys int) (model.ListObjectsResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.buckets[bucket]
	if !ok {
		return model.ListObjectsResult{}, ErrNoSuchBucket
	}
	res := model.ListObjectsResult{
		Bucket: bucket, Prefix: prefix, Delimiter: delimiter, Marker: marker, MaxKeys: maxKeys,
	}
	keys := make([]string, 0, len(b.objects))
	for k := range b.objects {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	seenPrefixes := map[string]bool{}
	count := 0
	truncated := false
	for _, key := range keys {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if delimiter != "" {
			rest := key[len(prefix):]
			if i := strings.Index(rest, delimiter); i >= 0 {
				common := prefix + rest[:i+len(delimiter)]
				if marker != "" && common <= marker {
					continue
				}
				if seenPrefixes[common] {
					continue
				}
				if maxKeys > 0 && count >= maxKeys {
					truncated = true
					break
				}
				seenPrefixes[common] = true
				res.CommonPrefixes = append(res.CommonPrefixes, common)
				count++
				continue
			}
		}
		if marker != "" && key <= marker {
			continue
		}
		if maxKeys > 0 && count >= maxKeys {
			truncated = true
			break
		}
		obj, err := m.HeadObject(ctx, bucket, key, "")
		if err != nil {
			continue
		}
		res.Objects = append(res.Objects, obj)
		count++
	}
	res.KeyCount = count
	res.IsTruncated = truncated
	if truncated {
		if len(res.CommonPrefixes) > 0 {
			res.NextMarker = res.CommonPrefixes[len(res.CommonPrefixes)-1]
		} else if len(res.Objects) > 0 {
			res.NextMarker = res.Objects[len(res.Objects)-1].Key
		}
	}
	return res, nil
}

func (m *Memory) ListObjectVersions(ctx context.Context, bucket, prefix, delimiter, keyMarker, versionIDMarker string, maxKeys int) (model.ListObjectVersionsResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.buckets[bucket]
	if !ok {
		return model.ListObjectVersionsResult{}, ErrNoSuchBucket
	}
	res := model.ListObjectVersionsResult{
		Bucket: bucket, Prefix: prefix, Delimiter: delimiter,
		KeyMarker: keyMarker, VersionIDMarker: versionIDMarker, MaxKeys: maxKeys,
	}
	keys := make([]string, 0, len(b.objects))
	for k := range b.objects {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	seenPrefixes := map[string]bool{}
	count := 0
	truncated := false
	for _, key := range keys {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if delimiter != "" {
			rest := key[len(prefix):]
			if i := strings.Index(rest, delimiter); i >= 0 {
				common := prefix + rest[:i+len(delimiter)]
				if keyMarker != "" && common <= keyMarker {
					continue
				}
				if seenPrefixes[common] {
					continue
				}
				if maxKeys > 0 && count >= maxKeys {
					truncated = true
					break
				}
				seenPrefixes[common] = true
				res.CommonPrefixes = append(res.CommonPrefixes, common)
				count++
				continue
			}
		}
		if keyMarker != "" && key < keyMarker {
			continue
		}
		obj, _ := b.objects[key]
		for _, v := range obj.versions {
			if keyMarker != "" && key == keyMarker && versionIDMarker != "" && v.info.VersionID > versionIDMarker {
				continue
			}
			if maxKeys > 0 && count >= maxKeys {
				truncated = true
				break
			}
			if v.deleted {
				res.DeleteMarkers = append(res.DeleteMarkers, v.info)
			} else {
				res.Versions = append(res.Versions, v.info)
			}
			res.NextKeyMarker = key
			res.NextVersionIDMarker = v.info.VersionID
			count++
		}
		if truncated {
			break
		}
	}
	res.IsTruncated = truncated
	return res, nil
}

func (m *Memory) CreateMultipartUpload(ctx context.Context, bucket, key string, opts model.PutOptions) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.buckets[bucket]; !ok {
		return "", ErrNoSuchBucket
	}
	uploadID := newVersionID()
	m.buckets[bucket].uploads[uploadID] = &memUpload{
		key: key, contentType: opts.ContentType, userMeta: opts.UserMetadata,
		initiated: TSNow(), parts: map[int]model.PartInfo{}, partData: map[int][]byte{},
	}
	return uploadID, nil
}

func (m *Memory) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, r io.Reader, size int64) (model.PartInfo, error) {
	if partNumber < 1 || partNumber > 10000 {
		return model.PartInfo{}, ErrInvalidPart
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return model.PartInfo{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.buckets[bucket]
	if !ok {
		return model.PartInfo{}, ErrNoSuchBucket
	}
	up, ok := b.uploads[uploadID]
	if !ok {
		return model.PartInfo{}, ErrNoSuchUpload
	}
	etag := fmt.Sprintf("%x", md5.Sum(data))
	pi := model.PartInfo{PartNumber: partNumber, ETag: etag, Size: int64(len(data)), LastModified: TSNow()}
	up.parts[partNumber] = pi
	up.partData[partNumber] = data
	return pi, nil
}

func (m *Memory) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []model.CompletedPart) (model.ObjectInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.buckets[bucket]
	if !ok {
		return model.ObjectInfo{}, ErrNoSuchBucket
	}
	up, ok := b.uploads[uploadID]
	if !ok {
		return model.ObjectInfo{}, ErrNoSuchUpload
	}
	if len(parts) > 0 {
		for i := 1; i < len(parts); i++ {
			if parts[i].PartNumber < parts[i-1].PartNumber {
				return model.ObjectInfo{}, ErrInvalidPartOrder
			}
		}
	}
	var buf bytes.Buffer
	h := md5.New()
	for _, p := range parts {
		data, ok := up.partData[p.PartNumber]
		if !ok {
			return model.ObjectInfo{}, ErrInvalidPart
		}
		if p.ETag != "" && p.ETag != up.parts[p.PartNumber].ETag {
			return model.ObjectInfo{}, ErrInvalidPart
		}
		buf.Write(data)
		h.Write(data)
	}
	versionID := "null"
	if b.versioning == "Enabled" {
		versionID = newVersionID()
	}
	info := model.ObjectInfo{
		Bucket: bucket, Key: key, VersionID: versionID,
		Size: int64(buf.Len()), ETag: fmt.Sprintf("%x", h.Sum(nil)),
		ContentType: up.contentType, UserMetadata: up.userMeta,
		LastModified: TSNow(), StorageClass: "STANDARD",
	}
	obj, ok := b.objects[key]
	if !ok {
		obj = &memObject{}
		b.objects[key] = obj
	}
	if b.versioning == "Enabled" {
		obj.versions = append([]*memVersion{{info: info, data: buf.Bytes()}}, obj.versions...)
	} else {
		obj.versions = []*memVersion{{info: info, data: buf.Bytes()}}
	}
	delete(b.uploads, uploadID)
	return info, nil
}

func (m *Memory) AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.buckets[bucket]
	if !ok {
		return ErrNoSuchBucket
	}
	if _, ok := b.uploads[uploadID]; !ok {
		return ErrNoSuchUpload
	}
	delete(b.uploads, uploadID)
	return nil
}

func (m *Memory) ListParts(ctx context.Context, bucket, key, uploadID string) ([]model.PartInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.buckets[bucket]
	if !ok {
		return nil, ErrNoSuchBucket
	}
	up, ok := b.uploads[uploadID]
	if !ok {
		return nil, ErrNoSuchUpload
	}
	parts := make([]model.PartInfo, 0, len(up.parts))
	for _, p := range up.parts {
		parts = append(parts, p)
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].PartNumber < parts[j].PartNumber })
	return parts, nil
}

func (m *Memory) ListMultipartUploads(ctx context.Context, bucket string) ([]model.MultipartUpload, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.buckets[bucket]
	if !ok {
		return nil, ErrNoSuchBucket
	}
	out := make([]model.MultipartUpload, 0, len(b.uploads))
	for id, up := range b.uploads {
		out = append(out, model.MultipartUpload{Bucket: bucket, Key: up.key, UploadID: id, Initiated: up.initiated})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func (m *Memory) findVersion(obj *memObject, versionID string) *memVersion {
	if len(obj.versions) == 0 {
		return nil
	}
	if versionID == "" {
		return obj.versions[0]
	}
	for _, v := range obj.versions {
		if v.info.VersionID == versionID {
			return v
		}
	}
	return nil
}

var _ Storage = (*Memory)(nil)
