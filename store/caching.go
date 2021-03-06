package store

import (
	"github.com/lbryio/lbry.go/v2/extras/errors"
	"github.com/lbryio/lbry.go/v2/stream"
)

// CachingBlobStore combines two stores, typically a local and a remote store, to improve performance.
// Accessed blobs are stored in and retrieved from the cache. If they are not in the cache, they
// are retrieved from the origin and cached. Puts are cached and also forwarded to the origin.
type CachingBlobStore struct {
	origin, cache BlobStore
}

// NewCachingBlobStore makes a new caching disk store and returns a pointer to it.
func NewCachingBlobStore(origin, cache BlobStore) *CachingBlobStore {
	return &CachingBlobStore{origin: origin, cache: cache}
}

// Has checks the cache and then the origin for a hash. It returns true if either store has it.
func (c *CachingBlobStore) Has(hash string) (bool, error) {
	has, err := c.cache.Has(hash)
	if has || err != nil {
		return has, err
	}
	return c.origin.Has(hash)
}

// Get tries to get the blob from the cache first, falling back to the origin. If the blob comes
// from the origin, it is also stored in the cache.
func (c *CachingBlobStore) Get(hash string) (stream.Blob, error) {
	blob, err := c.cache.Get(hash)
	if err == nil || !errors.Is(err, ErrBlobNotFound) {
		return blob, err
	}

	blob, err = c.origin.Get(hash)
	if err != nil {
		return nil, err
	}

	err = c.cache.Put(hash, blob)

	return blob, err
}

// Put stores the blob in the origin and the cache
func (c *CachingBlobStore) Put(hash string, blob stream.Blob) error {
	err := c.origin.Put(hash, blob)
	if err != nil {
		return err
	}
	return c.cache.Put(hash, blob)
}

// PutSD stores the sd blob in the origin and the cache
func (c *CachingBlobStore) PutSD(hash string, blob stream.Blob) error {
	err := c.origin.PutSD(hash, blob)
	if err != nil {
		return err
	}
	return c.cache.PutSD(hash, blob)
}

// Delete deletes the blob from the origin and the cache
func (c *CachingBlobStore) Delete(hash string) error {
	err := c.origin.Delete(hash)
	if err != nil {
		return err
	}
	return c.cache.Delete(hash)
}
