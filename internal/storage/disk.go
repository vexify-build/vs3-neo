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
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vs3-neo/vs3-neo/internal/model"
)

// default backend registration: disk + memory are always available.
func init() {
	_ = Register("disk", func(cfg map[string]string) (Storage, error) {
		dir := cfg["data_dir"]
		if dir == "" {
			dir = "./data"
		}
		return NewDisk(dir)
	})
	_ = Register("memory", func(cfg map[string]string) (Storage, error) {
		return NewMemory(), nil
	})
}

// Bucket name rules follow AWS S3: 3-63 chars, lowercase letters, digits,
// dots and hyphens, must start/end with a letter or digit.
var bucketNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$`)

// ValidateBucketName checks an S3 bucket name.
func ValidateBucketName(name string) error {
	if !bucketNameRe.MatchString(name) {
		return ErrInvalidBucketName
	}
	if strings.Contains(name, "..") || strings.Contains(name, ".-") || strings.Contains(name, "-.") {
		return ErrInvalidBucketName
	}
	return nil
}

// ---- metadata schemas (internal, persisted as JSON) ----

type bucketMeta struct {
	Name       string `json:"name"`
	Created    string `json:"created"`
	Versioning string `json:"versioning"`
}

type versionEntry struct {
	VersionID    string            `json:"versionId"`
	Size         int64             `json:"size"`
	ETag         string            `json:"etag"`
	ContentType  string            `json:"contentType"`
	UserMeta     map[string]string `json:"userMeta,omitempty"`
	LastModified string            `json:"lastModified"`
	DeleteMarker bool              `json:"isDeleteMarker,omitempty"`
}

type objectMeta struct {
	Key      string         `json:"key"`
	Versions []versionEntry `json:"versions"`
}

type uploadPart struct {
	PartNumber   int    `json:"partNumber"`
	ETag         string `json:"etag"`
	Size         int64  `json:"size"`
	LastModified string `json:"lastModified"`
}

type uploadMeta struct {
	Bucket     string            `json:"bucket"`
	Key        string            `json:"key"`
	UploadID   string            `json:"uploadId"`
	ContentType string           `json:"contentType"`
	UserMeta   map[string]string `json:"userMeta,omitempty"`
	Initiated  string            `json:"initiated"`
	Parts      []uploadPart      `json:"parts"`
}

// Disk implements Storage on the local filesystem.
type Disk struct {
	dataDir string
	// keyedLock serializes mutation of a given logical object / upload.
	keyedLock *keyedMutex
	// metaMu guards bucket metadata reads/writes per bucket.
	metaMu sync.RWMutex
}

// NewDisk creates a disk backend rooted at dir.
func NewDisk(dir string) (*Disk, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("disk: cannot create data dir %q: %w", dir, err)
	}
	return &Disk{dataDir: dir, keyedLock: newKeyedMutex()}, nil
}

// ---- path helpers ----

func (d *Disk) bucketDir(bucket string) string {
	return filepath.Join(d.dataDir, bucket)
}

func (d *Disk) bucketMetaPath(bucket string) string {
	return filepath.Join(d.bucketDir(bucket), "bucket.meta.json")
}

func (d *Disk) objectsDir(bucket string) string {
	return filepath.Join(d.bucketDir(bucket), "objects")
}

func (d *Disk) objectMetaPath(bucket, key string) string {
	return filepath.Join(d.objectsDir(bucket), hashKey(key)+".json")
}

func (d *Disk) dataDirPath(bucket string) string {
	return filepath.Join(d.objectsDir(bucket), "data")
}

func (d *Disk) dataFilePath(bucket, key, versionID string) string {
	return filepath.Join(d.dataDirPath(bucket), hashKey(key)+"-"+versionID+".bin")
}

func (d *Disk) uploadsDir(bucket string) string {
	return filepath.Join(d.bucketDir(bucket), "uploads")
}

func (d *Disk) uploadMetaPath(bucket, uploadID string) string {
	return filepath.Join(d.uploadsDir(bucket), uploadID+".json")
}

func (d *Disk) uploadPartsDir(bucket, uploadID string) string {
	return filepath.Join(d.uploadsDir(bucket), uploadID, "parts")
}

func (d *Disk) uploadPartPath(bucket, uploadID string, partNumber int) string {
	return filepath.Join(d.uploadPartsDir(bucket, uploadID), fmt.Sprintf("%05d.part", partNumber))
}

// hashKey maps a logical object key to a filesystem-safe name.
func hashKey(key string) string {
	sum := md5.Sum([]byte(key))
	return hex.EncodeToString(sum[:])
}

// newVersionID returns a random version/upload identifier.
func newVersionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// ---- generic JSON read/write ----

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ---- bucket operations ----

func (d *Disk) CreateBucket(ctx context.Context, bucket string) error {
	if err := ValidateBucketName(bucket); err != nil {
		return err
	}
	d.metaMu.Lock()
	defer d.metaMu.Unlock()
	if fileExists(d.bucketMetaPath(bucket)) {
		return ErrBucketAlreadyExists
	}
	bm := bucketMeta{Name: bucket, Created: TSNow().Format(time.RFC3339)}
	return writeJSON(d.bucketMetaPath(bucket), bm)
}

func (d *Disk) DeleteBucket(ctx context.Context, bucket string) error {
	d.metaMu.Lock()
	defer d.metaMu.Unlock()
	if !fileExists(d.bucketMetaPath(bucket)) {
		return ErrNoSuchBucket
	}
	// Refuse to delete a non-empty bucket.
	empty, err := d.bucketEmpty(bucket)
	if err != nil {
		return err
	}
	if !empty {
		return ErrBucketNotEmpty
	}
	return os.RemoveAll(d.bucketDir(bucket))
}

func (d *Disk) bucketEmpty(bucket string) (bool, error) {
	entries, err := os.ReadDir(d.uploadsDir(bucket))
	if err == nil && len(entries) > 0 {
		return false, nil
	}
	objDir := d.objectsDir(bucket)
	if !fileExists(objDir) {
		return true, nil
	}
	entries, err = os.ReadDir(objDir)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if e.Name() == "data" {
			continue
		}
		return false, nil
	}
	return true, nil
}

func (d *Disk) ListBuckets(ctx context.Context) ([]model.BucketInfo, error) {
	d.metaMu.RLock()
	defer d.metaMu.RUnlock()
	entries, err := os.ReadDir(d.dataDir)
	if err != nil {
		return nil, err
	}
	var out []model.BucketInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var bm bucketMeta
		if err := readJSON(filepath.Join(d.dataDir, e.Name(), "bucket.meta.json"), &bm); err != nil {
			continue
		}
		created, _ := time.Parse(time.RFC3339, bm.Created)
		out = append(out, model.BucketInfo{Name: bm.Name, CreationDate: created})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (d *Disk) BucketExists(ctx context.Context, bucket string) (bool, error) {
	d.metaMu.RLock()
	defer d.metaMu.RUnlock()
	return fileExists(d.bucketMetaPath(bucket)), nil
}

// ---- versioning ----

func (d *Disk) GetVersioning(ctx context.Context, bucket string) (string, error) {
	d.metaMu.RLock()
	defer d.metaMu.RUnlock()
	var bm bucketMeta
	if err := readJSON(d.bucketMetaPath(bucket), &bm); err != nil {
		return "", ErrNoSuchBucket
	}
	return bm.Versioning, nil
}

func (d *Disk) SetVersioning(ctx context.Context, bucket, status string) error {
	d.metaMu.Lock()
	defer d.metaMu.Unlock()
	var bm bucketMeta
	if err := readJSON(d.bucketMetaPath(bucket), &bm); err != nil {
		return ErrNoSuchBucket
	}
	if status != "" && status != "Enabled" && status != "Suspended" {
		return fmt.Errorf("%w: invalid versioning status %q", ErrInvalidVersion, status)
	}
	bm.Versioning = status
	return writeJSON(d.bucketMetaPath(bucket), bm)
}

// ---- object operations ----

func (d *Disk) PutObject(ctx context.Context, bucket, key string, r io.Reader, size int64, opts model.PutOptions) (model.ObjectInfo, error) {
	d.metaMu.RLock()
	if !fileExists(d.bucketMetaPath(bucket)) {
		d.metaMu.RUnlock()
		return model.ObjectInfo{}, ErrNoSuchBucket
	}
	ver, _ := d.versioningLocked(bucket)
	d.metaMu.RUnlock()

	unlock := d.keyedLock.Lock(bucket + "/" + key)
	defer unlock()

	// Determine version id: when versioning is Enabled every put creates a
	// new version; otherwise the version slot is "null" (overwrite in place).
	versionID := "null"
	if ver == "Enabled" {
		versionID = newVersionID()
	}
	fpath := d.dataFilePath(bucket, key, versionID)

	// Stream to a temp file first, computing md5 while writing.
	tmp := fpath + ".tmp"
	if err := os.MkdirAll(filepath.Dir(fpath), 0o755); err != nil {
		return model.ObjectInfo{}, err
	}
	f, err := os.Create(tmp)
	if err != nil {
		return model.ObjectInfo{}, err
	}
	h := md5.New()
	n, err := io.Copy(io.MultiWriter(f, h), r)
	if err != nil {
		f.Close()
		os.Remove(tmp)
		return model.ObjectInfo{}, err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return model.ObjectInfo{}, err
	}

	om := d.readObjectMeta(bucket, key)
	// For non-versioned overwrites, drop the previous data file BEFORE the
	// rename (old and new share the "null" path).
	if ver != "Enabled" {
		for _, v := range om.Versions {
			d.removeDataFile(bucket, key, v)
		}
	}
	if err := os.Rename(tmp, fpath); err != nil {
		os.Remove(tmp)
		return model.ObjectInfo{}, err
	}

	etag := hex.EncodeToString(h.Sum(nil))
	now := TSNow()
	entry := versionEntry{
		VersionID:    versionID,
		Size:         n,
		ETag:         etag,
		ContentType:  opts.ContentType,
		UserMeta:     opts.UserMetadata,
		LastModified: now.Format(time.RFC3339),
	}

	// Update logical object metadata.
	if ver == "Enabled" {
		// Keep the newest version first; trim to a sane cap.
		om.Versions = append([]versionEntry{entry}, om.Versions...)
		if len(om.Versions) > 100 {
			d.removeDataFile(bucket, key, om.Versions[len(om.Versions)-1])
			om.Versions = om.Versions[:100]
		}
	} else {
		om.Versions = []versionEntry{entry}
	}
	om.Key = key
	if err := writeJSON(d.objectMetaPath(bucket, key), om); err != nil {
		return model.ObjectInfo{}, err
	}

	return entry.toObjectInfo(bucket, key), nil
}

func (d *Disk) GetObject(ctx context.Context, bucket, key, versionID string, off, length int64) (GetObjectResult, error) {
	obj, err := d.HeadObject(ctx, bucket, key, versionID)
	if err != nil {
		return GetObjectResult{}, err
	}
	fpath := d.dataFilePath(bucket, key, obj.VersionID)
	f, err := os.Open(fpath)
	if err != nil {
		return GetObjectResult{}, ErrNoSuchKey
	}
	var body io.ReadCloser = f
	if off >= 0 {
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			f.Close()
			return GetObjectResult{}, err
		}
		if length >= 0 {
			body = &limitedReadCloser{R: io.LimitReader(f, length), C: f}
		}
	}
	return GetObjectResult{Object: obj, Body: body}, nil
}

type limitedReadCloser struct {
	R io.Reader
	C io.Closer
}

func (l *limitedReadCloser) Read(p []byte) (int, error) { return l.R.Read(p) }
func (l *limitedReadCloser) Close() error               { return l.C.Close() }

func (d *Disk) HeadObject(ctx context.Context, bucket, key, versionID string) (model.ObjectInfo, error) {
	d.metaMu.RLock()
	if !fileExists(d.bucketMetaPath(bucket)) {
		d.metaMu.RUnlock()
		return model.ObjectInfo{}, ErrNoSuchBucket
	}
	d.metaMu.RUnlock()

	unlock := d.keyedLock.RLock(bucket + "/" + key)
	defer unlock()

	om := d.readObjectMeta(bucket, key)
	idx := 0
	if versionID != "" {
		found := false
		for i, v := range om.Versions {
			if v.VersionID == versionID {
				idx = i
				found = true
				break
			}
		}
		if !found {
			return model.ObjectInfo{}, ErrNoSuchKey
		}
	}
	if len(om.Versions) == 0 {
		return model.ObjectInfo{}, ErrNoSuchKey
	}
	obj := om.Versions[idx].toObjectInfo(bucket, key)
	if obj.IsDeleteMarker {
		return model.ObjectInfo{}, ErrNoSuchKey
	}
	return obj, nil
}

func (d *Disk) DeleteObject(ctx context.Context, bucket, key, versionID string) (model.ObjectInfo, error) {
	d.metaMu.RLock()
	if !fileExists(d.bucketMetaPath(bucket)) {
		d.metaMu.RUnlock()
		return model.ObjectInfo{}, ErrNoSuchBucket
	}
	ver, _ := d.versioningLocked(bucket)
	d.metaMu.RUnlock()

	unlock := d.keyedLock.Lock(bucket + "/" + key)
	defer unlock()

	om := d.readObjectMeta(bucket, key)
	if len(om.Versions) == 0 {
		// Deleting a non-existent key with versioning enabled still creates
		// a delete marker per S3 semantics.
		if ver == "Enabled" {
			marker := versionEntry{
				VersionID:    newVersionID(),
				DeleteMarker: true,
				LastModified: TSNow().Format(time.RFC3339),
			}
			om.Versions = append([]versionEntry{marker}, om.Versions...)
			writeJSON(d.objectMetaPath(bucket, key), om)
			return marker.toObjectInfo(bucket, key), nil
		}
		return model.ObjectInfo{}, nil
	}

	if versionID != "" {
		// Delete a specific version.
		for i, v := range om.Versions {
			if v.VersionID == versionID {
				d.removeDataFile(bucket, key, v)
				om.Versions = append(om.Versions[:i], om.Versions[i+1:]...)
				if len(om.Versions) == 0 {
					os.Remove(d.objectMetaPath(bucket, key))
				} else {
					writeJSON(d.objectMetaPath(bucket, key), om)
				}
				return v.toObjectInfo(bucket, key), nil
			}
		}
		return model.ObjectInfo{}, ErrNoSuchKey
	}

	// Delete latest. With versioning enabled, insert a delete marker instead.
	if ver == "Enabled" {
		marker := versionEntry{
			VersionID:    newVersionID(),
			DeleteMarker: true,
			LastModified: TSNow().Format(time.RFC3339),
		}
		om.Versions = append([]versionEntry{marker}, om.Versions...)
		writeJSON(d.objectMetaPath(bucket, key), om)
		return marker.toObjectInfo(bucket, key), nil
	}

	// Versioning off: remove the single version and metadata.
	for _, v := range om.Versions {
		d.removeDataFile(bucket, key, v)
	}
	os.Remove(d.objectMetaPath(bucket, key))
	return om.Versions[0].toObjectInfo(bucket, key), nil
}

func (d *Disk) CopyObject(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string, opts model.PutOptions) (model.CopyObjectResult, error) {
	src, err := d.GetObject(ctx, srcBucket, srcKey, "", -1, -1)
	if err != nil {
		return model.CopyObjectResult{}, err
	}
	defer src.Body.Close()
	info, err := d.PutObject(ctx, dstBucket, dstKey, src.Body, src.Object.Size, opts)
	if err != nil {
		return model.CopyObjectResult{}, err
	}
	return model.CopyObjectResult{
		ETag:         info.ETag,
		LastModified: info.LastModified,
		Object:       info,
	}, nil
}

func (d *Disk) ListObjects(ctx context.Context, bucket, prefix, delimiter, marker string, maxKeys int) (model.ListObjectsResult, error) {
	d.metaMu.RLock()
	if !fileExists(d.bucketMetaPath(bucket)) {
		d.metaMu.RUnlock()
		return model.ListObjectsResult{}, ErrNoSuchBucket
	}
	d.metaMu.RUnlock()

	res := model.ListObjectsResult{
		Bucket: bucket, Prefix: prefix, Delimiter: delimiter, Marker: marker, MaxKeys: maxKeys,
	}
	keys := d.collectObjectMetaKeys(bucket)
	sort.Strings(keys)

	seenPrefixes := map[string]bool{}
	truncated := false
	count := 0
	for _, key := range keys {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		rest := key[len(prefix):]
		if delimiter != "" {
			if i := strings.Index(rest, delimiter); i >= 0 {
				common := prefix + rest[:i+len(delimiter)]
				if common <= marker && marker != "" {
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
		obj, err := d.HeadObject(ctx, bucket, key, "")
		if err != nil {
			continue // skip delete markers / missing
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

func (d *Disk) ListObjectVersions(ctx context.Context, bucket, prefix, delimiter, keyMarker, versionIDMarker string, maxKeys int) (model.ListObjectVersionsResult, error) {
	d.metaMu.RLock()
	if !fileExists(d.bucketMetaPath(bucket)) {
		d.metaMu.RUnlock()
		return model.ListObjectVersionsResult{}, ErrNoSuchBucket
	}
	d.metaMu.RUnlock()

	res := model.ListObjectVersionsResult{
		Bucket: bucket, Prefix: prefix, Delimiter: delimiter,
		KeyMarker: keyMarker, VersionIDMarker: versionIDMarker, MaxKeys: maxKeys,
	}
	keys := d.collectObjectMetaKeys(bucket)
	sort.Strings(keys)
	seenPrefixes := map[string]bool{}
	count := 0
	truncated := false

	// For each key (sorted), list versions newest-first, with delete markers.
	for _, key := range keys {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if delimiter != "" {
			rest := key[len(prefix):]
			if i := strings.Index(rest, delimiter); i >= 0 {
				common := prefix + rest[:i+len(delimiter)]
				if common <= keyMarker && keyMarker != "" {
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
		om := d.readObjectMeta(bucket, key)
		for _, v := range om.Versions {
			if keyMarker != "" && key == keyMarker && versionIDMarker != "" && v.VersionID > versionIDMarker {
				continue
			}
			if maxKeys > 0 && count >= maxKeys {
				truncated = true
				break
			}
			info := v.toObjectInfo(bucket, key)
			if v.DeleteMarker {
				res.DeleteMarkers = append(res.DeleteMarkers, info)
			} else {
				res.Versions = append(res.Versions, info)
			}
			res.NextKeyMarker = key
			res.NextVersionIDMarker = v.VersionID
			count++
		}
		if truncated {
			break
		}
	}
	res.IsTruncated = truncated
	return res, nil
}

// ---- multipart ----

func (d *Disk) CreateMultipartUpload(ctx context.Context, bucket, key string, opts model.PutOptions) (string, error) {
	d.metaMu.RLock()
	if !fileExists(d.bucketMetaPath(bucket)) {
		d.metaMu.RUnlock()
		return "", ErrNoSuchBucket
	}
	d.metaMu.RUnlock()

	uploadID := newVersionID()
	um := uploadMeta{
		Bucket: bucket, Key: key, UploadID: uploadID,
		ContentType: opts.ContentType, UserMeta: opts.UserMetadata,
		Initiated: TSNow().Format(time.RFC3339),
	}
	if err := writeJSON(d.uploadMetaPath(bucket, uploadID), um); err != nil {
		return "", err
	}
	return uploadID, nil
}

func (d *Disk) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int, r io.Reader, size int64) (model.PartInfo, error) {
	unlock := d.keyedLock.Lock(bucket + "/uploads/" + uploadID)
	defer unlock()

	if !fileExists(d.uploadMetaPath(bucket, uploadID)) {
		return model.PartInfo{}, ErrNoSuchUpload
	}
	if partNumber < 1 || partNumber > 10000 {
		return model.PartInfo{}, ErrInvalidPart
	}
	path := d.uploadPartPath(bucket, uploadID, partNumber)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return model.PartInfo{}, err
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return model.PartInfo{}, err
	}
	h := md5.New()
	n, err := io.Copy(io.MultiWriter(f, h), r)
	if err != nil {
		f.Close()
		os.Remove(tmp)
		return model.PartInfo{}, err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return model.PartInfo{}, err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return model.PartInfo{}, err
	}

	etag := hex.EncodeToString(h.Sum(nil))
	now := TSNow()
	// Update upload metadata with the part record.
	um, err := d.readUploadMeta(bucket, uploadID)
	if err != nil {
		return model.PartInfo{}, err
	}
	found := false
	for i := range um.Parts {
		if um.Parts[i].PartNumber == partNumber {
			um.Parts[i] = uploadPart{PartNumber: partNumber, ETag: etag, Size: n, LastModified: now.Format(time.RFC3339)}
			found = true
			break
		}
	}
	if !found {
		um.Parts = append(um.Parts, uploadPart{PartNumber: partNumber, ETag: etag, Size: n, LastModified: now.Format(time.RFC3339)})
	}
	if err := writeJSON(d.uploadMetaPath(bucket, uploadID), um); err != nil {
		return model.PartInfo{}, err
	}
	return model.PartInfo{PartNumber: partNumber, ETag: etag, Size: n, LastModified: now}, nil
}

func (d *Disk) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []model.CompletedPart) (model.ObjectInfo, error) {
	unlock := d.keyedLock.Lock(bucket + "/uploads/" + uploadID)
	defer unlock()

	um, err := d.readUploadMeta(bucket, uploadID)
	if err != nil {
		return model.ObjectInfo{}, err
	}

	// Validate: parts must be in ascending order and all exist.
	byNum := map[int]model.CompletedPart{}
	for _, p := range parts {
		byNum[p.PartNumber] = p
	}
	if len(parts) > 0 {
		for i := 1; i < len(parts); i++ {
			if parts[i].PartNumber < parts[i-1].PartNumber {
				return model.ObjectInfo{}, ErrInvalidPartOrder
			}
		}
	}
	umParts := map[int]uploadPart{}
	for _, p := range um.Parts {
		umParts[p.PartNumber] = p
	}

	d.metaMu.RLock()
	ver, _ := d.versioningLocked(bucket)
	d.metaMu.RUnlock()

	versionID := "null"
	if ver == "Enabled" {
		versionID = newVersionID()
	}

	fpath := d.dataFilePath(bucket, key, versionID)
	if err := os.MkdirAll(filepath.Dir(fpath), 0o755); err != nil {
		return model.ObjectInfo{}, err
	}
	tmp := fpath + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return model.ObjectInfo{}, err
	}
	h := md5.New()
	var total int64
	cleanup := func() { out.Close(); os.Remove(tmp) }
	for _, p := range parts {
		up, ok := umParts[p.PartNumber]
		if !ok {
			cleanup()
			return model.ObjectInfo{}, ErrInvalidPart
		}
		// Optional etag check.
		if p.ETag != "" && p.ETag != up.ETag {
			cleanup()
			return model.ObjectInfo{}, ErrInvalidPart
		}
		partFile, err := os.Open(d.uploadPartPath(bucket, uploadID, p.PartNumber))
		if err != nil {
			cleanup()
			return model.ObjectInfo{}, ErrInvalidPart
		}
		n, err := io.Copy(io.MultiWriter(out, h), partFile)
		partFile.Close()
		if err != nil {
			cleanup()
			return model.ObjectInfo{}, err
		}
		total += n
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return model.ObjectInfo{}, err
	}

	om := d.readObjectMeta(bucket, key)
	// Non-versioned: drop previous data file (same "null" path) before rename.
	if ver != "Enabled" {
		for _, v := range om.Versions {
			d.removeDataFile(bucket, key, v)
		}
	}
	if err := os.Rename(tmp, fpath); err != nil {
		os.Remove(tmp)
		return model.ObjectInfo{}, err
	}

	etag := hex.EncodeToString(h.Sum(nil))
	now := TSNow()
	entry := versionEntry{
		VersionID:    versionID,
		Size:         total,
		ETag:         etag,
		ContentType:  um.ContentType,
		UserMeta:     um.UserMeta,
		LastModified: now.Format(time.RFC3339),
	}
	if ver == "Enabled" {
		om.Versions = append([]versionEntry{entry}, om.Versions...)
		if len(om.Versions) > 100 {
			d.removeDataFile(bucket, key, om.Versions[len(om.Versions)-1])
			om.Versions = om.Versions[:100]
		}
	} else {
		om.Versions = []versionEntry{entry}
	}
	om.Key = key
	if err := writeJSON(d.objectMetaPath(bucket, key), om); err != nil {
		return model.ObjectInfo{}, err
	}

	// Remove upload artifacts.
	os.RemoveAll(d.uploadsDir(bucket) + string(os.PathSeparator) + uploadID)
	os.Remove(d.uploadMetaPath(bucket, uploadID))

	return entry.toObjectInfo(bucket, key), nil
}

func (d *Disk) AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error {
	unlock := d.keyedLock.Lock(bucket + "/uploads/" + uploadID)
	defer unlock()
	if !fileExists(d.uploadMetaPath(bucket, uploadID)) {
		return ErrNoSuchUpload
	}
	os.RemoveAll(d.uploadPartsDir(bucket, uploadID))
	os.RemoveAll(d.uploadsDir(bucket) + string(os.PathSeparator) + uploadID)
	return os.Remove(d.uploadMetaPath(bucket, uploadID))
}

func (d *Disk) ListParts(ctx context.Context, bucket, key, uploadID string) ([]model.PartInfo, error) {
	unlock := d.keyedLock.RLock(bucket + "/uploads/" + uploadID)
	defer unlock()
	um, err := d.readUploadMeta(bucket, uploadID)
	if err != nil {
		return nil, err
	}
	parts := make([]model.PartInfo, 0, len(um.Parts))
	for _, p := range um.Parts {
		t, _ := time.Parse(time.RFC3339, p.LastModified)
		parts = append(parts, model.PartInfo{PartNumber: p.PartNumber, ETag: p.ETag, Size: p.Size, LastModified: t})
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].PartNumber < parts[j].PartNumber })
	return parts, nil
}

func (d *Disk) ListMultipartUploads(ctx context.Context, bucket string) ([]model.MultipartUpload, error) {
	d.metaMu.RLock()
	if !fileExists(d.bucketMetaPath(bucket)) {
		d.metaMu.RUnlock()
		return nil, ErrNoSuchBucket
	}
	d.metaMu.RUnlock()

	entries, err := os.ReadDir(d.uploadsDir(bucket))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []model.MultipartUpload
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var um uploadMeta
		if err := readJSON(filepath.Join(d.uploadsDir(bucket), e.Name()), &um); err != nil {
			continue
		}
		t, _ := time.Parse(time.RFC3339, um.Initiated)
		out = append(out, model.MultipartUpload{
			Bucket: bucket, Key: um.Key, UploadID: um.UploadID, Initiated: t,
		})
	}
	return out, nil
}

// ---- internal helpers ----

func (d *Disk) versioningLocked(bucket string) (string, error) {
	var bm bucketMeta
	if err := readJSON(d.bucketMetaPath(bucket), &bm); err != nil {
		return "", ErrNoSuchBucket
	}
	return bm.Versioning, nil
}

func (d *Disk) readObjectMeta(bucket, key string) objectMeta {
	var om objectMeta
	_ = readJSON(d.objectMetaPath(bucket, key), &om)
	return om
}

func (d *Disk) readUploadMeta(bucket, uploadID string) (uploadMeta, error) {
	var um uploadMeta
	if err := readJSON(d.uploadMetaPath(bucket, uploadID), &um); err != nil {
		return um, ErrNoSuchUpload
	}
	return um, nil
}

func (d *Disk) collectObjectMetaKeys(bucket string) []string {
	dir := d.objectsDir(bucket)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	keys := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var om objectMeta
		if err := readJSON(filepath.Join(dir, e.Name()), &om); err != nil {
			continue
		}
		if len(om.Versions) > 0 {
			keys = append(keys, om.Key)
		}
	}
	return keys
}

func (d *Disk) removeDataFile(bucket, key string, v versionEntry) {
	// Only remove data files we own (hash-key based).
	path := d.dataFilePath(bucket, key, v.VersionID)
	_ = os.Remove(path)
}

func (v versionEntry) toObjectInfo(bucket, key string) model.ObjectInfo {
	t, _ := time.Parse(time.RFC3339, v.LastModified)
	info := model.ObjectInfo{
		Bucket:        bucket,
		Key:           key,
		VersionID:     v.VersionID,
		Size:          v.Size,
		ETag:          v.ETag,
		ContentType:   v.ContentType,
		UserMetadata:  v.UserMeta,
		LastModified:  t,
		IsDeleteMarker: v.DeleteMarker,
		StorageClass:  "STANDARD",
	}
	return info
}

// ---- keyed mutex ----

type keyedMutex struct {
	mu sync.Mutex
	m  map[string]*refCounter
}

type refCounter struct {
	mu  sync.Mutex
	ref int
}

func newKeyedMutex() *keyedMutex {
	return &keyedMutex{m: map[string]*refCounter{}}
}

// Lock returns a release func. The first caller creates the entry.
func (k *keyedMutex) Lock(key string) func() {
	return k.lock(key, true)
}

// RLock returns a release func (shared). For simplicity we share the same
// mutex implementation as Lock; ref counting keeps entries cleaned up.
func (k *keyedMutex) RLock(key string) func() {
	return k.lock(key, true)
}

func (k *keyedMutex) lock(key string, exclusive bool) func() {
	k.mu.Lock()
	rc, ok := k.m[key]
	if !ok {
		rc = &refCounter{}
		k.m[key] = rc
	}
	rc.ref++
	k.mu.Unlock()

	rc.mu.Lock()
	released := false
	return func() {
		if released {
			return
		}
		released = true
		rc.mu.Unlock()
		k.mu.Lock()
		rc.ref--
		if rc.ref == 0 {
			delete(k.m, key)
		}
		k.mu.Unlock()
	}
}

// ensure Disk implements Storage.
var _ Storage = (*Disk)(nil)
