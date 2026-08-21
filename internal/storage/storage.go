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

// Package storage defines the pluggable storage backend interface for vs3-neo.
//
// vs3-neo ships with two backends: "disk" (default, persists to local disk)
// and "memory" (ephemeral, useful for tests and demos). Additional backends
// (S3 gateway, Ceph/RADOS, cloud storage, databases...) can be plugged in by
// implementing the Storage interface and registering a factory with Register.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/vs3-neo/vs3-neo/internal/model"
)

// Sentinel errors. These are translated to S3 error codes by the API layer.
var (
	ErrBucketAlreadyExists = errors.New("BucketAlreadyOwnedByYou")
	ErrNoSuchBucket        = errors.New("NoSuchBucket")
	ErrNoSuchKey           = errors.New("NoSuchKey")
	ErrNoSuchUpload        = errors.New("NoSuchUpload")
	ErrInvalidPartOrder    = errors.New("InvalidPartOrder")
	ErrInvalidPart         = errors.New("InvalidPart")
	ErrInvalidRange        = errors.New("InvalidRange")
	ErrNotImplemented      = errors.New("NotImplemented")
	ErrInternal            = errors.New("InternalError")
	ErrMethodNotAllowed    = errors.New("MethodNotAllowed")
	ErrInvalidBucketName   = errors.New("InvalidBucketName")
	ErrBucketNotEmpty      = errors.New("BucketNotEmpty")
	ErrInvalidVersion      = errors.New("InvalidArgument")
)

// GetObjectResult pairs object metadata with a streaming body.
type GetObjectResult struct {
	Object model.ObjectInfo
	Body   io.ReadCloser
}

// Storage is the pluggable backend interface. Every operation receives a
// context for cancellation/deadlines.
type Storage interface {
	// ---- Bucket operations ----
	CreateBucket(ctx context.Context, bucket string) error
	DeleteBucket(ctx context.Context, bucket string) error
	ListBuckets(ctx context.Context) ([]model.BucketInfo, error)
	BucketExists(ctx context.Context, bucket string) (bool, error)

	// ---- Versioning ----
	// GetVersioning returns "" (unset), "Enabled" or "Suspended".
	GetVersioning(ctx context.Context, bucket string) (string, error)
	SetVersioning(ctx context.Context, bucket, status string) error

	// ---- Object operations ----
	PutObject(ctx context.Context, bucket, key string, r io.Reader, size int64, opts model.PutOptions) (model.ObjectInfo, error)
	GetObject(ctx context.Context, bucket, key, versionID string) (GetObjectResult, error)
	HeadObject(ctx context.Context, bucket, key, versionID string) (model.ObjectInfo, error)
	DeleteObject(ctx context.Context, bucket, key, versionID string) (model.ObjectInfo, error)
	CopyObject(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string, opts model.PutOptions) (model.CopyObjectResult, error)
	ListObjects(ctx context.Context, bucket, prefix, delimiter, marker string, maxKeys int) (model.ListObjectsResult, error)
	ListObjectVersions(ctx context.Context, bucket, prefix, delimiter, keyMarker, versionIDMarker string, maxKeys int) (model.ListObjectVersionsResult, error)

	// ---- Multipart upload operations ----
	CreateMultipartUpload(ctx context.Context, bucket, key string, opts model.PutOptions) (string, error)
	UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, r io.Reader, size int64) (model.PartInfo, error)
	CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []model.CompletedPart) (model.ObjectInfo, error)
	AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error
	ListParts(ctx context.Context, bucket, key, uploadID string) ([]model.PartInfo, error)
	ListMultipartUploads(ctx context.Context, bucket string) ([]model.MultipartUpload, error)
}

// Factory constructs a storage backend from configuration.
type Factory func(cfg map[string]string) (Storage, error)

var (
	registryMtx sync.RWMutex
	registry    = map[string]Factory{}
)

// Register adds a named backend factory. It is safe to call from init().
func Register(name string, f Factory) error {
	registryMtx.Lock()
	defer registryMtx.Unlock()
	if name == "" {
		return errors.New("storage: backend name must not be empty")
	}
	if _, dup := registry[name]; dup {
		return fmt.Errorf("storage: backend %q already registered", name)
	}
	registry[name] = f
	return nil
}

// New creates a storage backend by name, passing cfg as a string map.
func New(name string, cfg map[string]string) (Storage, error) {
	registryMtx.RLock()
	f, ok := registry[name]
	registryMtx.RUnlock()
	if !ok {
		return nil, fmt.Errorf("storage: unknown backend %q (available: %s)", name, Available())
	}
	return f(cfg)
}

// Available returns the sorted list of registered backend names.
func Available() string {
	registryMtx.RLock()
	defer registryMtx.RUnlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return join(names, ", ")
}

func join(xs []string, sep string) string {
	s := ""
	for i, x := range xs {
		if i > 0 {
			s += sep
		}
		s += x
	}
	return s
}

// TSNow returns the current UTC time truncated to seconds (a convenient
// timestamp for S3 metadata).
func TSNow() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}
