package kv

import (
	"errors"
	"time"

	"github.com/nats-io/nats.go"
)

var (
	mgr nats.KeyValueManager
)

var (
	ErrKVUninitialized = errors.New("KV subsystem is uninitialized")
)

// InitializeKV must be called before anything else. It's safe to call multiple times.
func InitializeKV(js nats.JetStreamContext) {
	if mgr == nil {
		mgr = js
	}
}

// DefaultKVConfig returns a configuration with "mostly sane" defaults. Override
// with the following Option functions
func DefaultKVConfig(bucketName string) *nats.KeyValueConfig {
	return &nats.KeyValueConfig{
		Bucket: bucketName,
		// the zero-value for StorageType gives us file storage (as opposed to memory)
		// the other zero-values should yield a functional config
	}
}

type Option func(c *nats.KeyValueConfig)

func WithTTL(d time.Duration) Option {
	return func(c *nats.KeyValueConfig) {
		c.TTL = d
	}
}

func WithReplicas(replicas int) Option {
	return func(c *nats.KeyValueConfig) {
		c.Replicas = replicas
	}
}

func WithDescription(desc string) Option {
	return func(c *nats.KeyValueConfig) {
		c.Description = desc
	}
}

// XXX: Not really sure we'd ever change this but...
func WithStorageType(st nats.StorageType) Option {
	return func(c *nats.KeyValueConfig) {
		c.Storage = st
	}
}

func CreateOrBindKVBucket(bucketName string, opts ...Option) (nats.KeyValue, error) {
	if mgr == nil {
		return nil, ErrKVUninitialized
	}
	kv, err := mgr.KeyValue(bucketName)
	if errors.Is(err, nats.ErrBucketNotFound) {
		cfg := DefaultKVConfig(bucketName)
		for _, o := range opts {
			o(cfg)
		}
		return mgr.CreateKeyValue(cfg)
	}
	return kv, err
}
