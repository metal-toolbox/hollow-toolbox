//nolint:wsl
package kv

import (
	"errors"
	"time"

	"github.com/nats-io/nats.go"

	"go.hollow.sh/toolbox/events"
)

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

func CreateOrBindKVBucket(handle *events.NatsJetstream, bucketName string,
	opts ...Option) (nats.KeyValue, error) {
	kv, err := events.AsNatsJetStreamContext(handle).KeyValue(bucketName)
	if errors.Is(err, nats.ErrBucketNotFound) {
		cfg := DefaultKVConfig(bucketName)
		for _, o := range opts {
			o(cfg)
		}
		return events.AsNatsJetStreamContext(handle).CreateKeyValue(cfg)
	}
	return kv, err
}
