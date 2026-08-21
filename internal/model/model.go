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

// Package model defines the shared data types used across vs3-neo.
package model

import "time"

// BucketInfo describes a bucket.
type BucketInfo struct {
	Name         string
	CreationDate time.Time
}

// ObjectInfo describes a stored object (a single version).
type ObjectInfo struct {
	Bucket        string
	Key           string
	VersionID     string
	Size          int64
	ETag          string
	ContentType   string
	LastModified  time.Time
	UserMetadata  map[string]string
	IsDeleteMarker bool
	StorageClass  string
}

// PartInfo describes one uploaded part of a multipart upload.
type PartInfo struct {
	PartNumber   int
	ETag         string
	Size         int64
	LastModified time.Time
}

// MultipartUpload describes an in-progress multipart upload.
type MultipartUpload struct {
	Bucket     string
	Key        string
	UploadID   string
	Initiated  time.Time
	StorageClass string
}

// ListObjectsResult is the result of a ListObjects (V1/V2) call.
type ListObjectsResult struct {
	Bucket         string
	Prefix         string
	Delimiter      string
	Marker         string
	NextMarker     string
	MaxKeys        int
	IsTruncated    bool
	EncodingType   string
	Objects        []ObjectInfo
	CommonPrefixes []string
	KeyCount       int
}

// ListObjectVersionsResult is the result of a ListObjectVersions call.
type ListObjectVersionsResult struct {
	Bucket             string
	Prefix             string
	Delimiter          string
	KeyMarker          string
	VersionIDMarker    string
	NextKeyMarker      string
	NextVersionIDMarker string
	MaxKeys            int
	IsTruncated        bool
	Versions           []ObjectInfo
	DeleteMarkers      []ObjectInfo
	CommonPrefixes     []string
}

// PutOptions carries optional metadata for object writes.
type PutOptions struct {
	ContentType  string
	UserMetadata map[string]string
}

// CopyObjectResult is returned by CopyObject.
type CopyObjectResult struct {
	ETag         string
	LastModified time.Time
	Object       ObjectInfo
}

// CompletedPart is used to complete a multipart upload.
type CompletedPart struct {
	PartNumber int
	ETag       string
}
