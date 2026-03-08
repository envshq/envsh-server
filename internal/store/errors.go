package store

import "errors"

// Sentinel errors returned by store implementations.
var (
	ErrNotFound       = errors.New("not found")
	ErrDuplicateEmail = errors.New("email already exists")
	ErrDuplicateSlug  = errors.New("slug already exists")
	ErrDuplicateKey   = errors.New("key already registered")
	ErrPushConflict   = errors.New("version conflict: base_version mismatch")
	ErrRevoked        = errors.New("resource has been revoked")
)
