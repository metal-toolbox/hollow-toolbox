// The registry package builds functionality for tracking live worker processes
// in a NATS KV store. The store is configured with replication and with a
// default 3 minute TTL for keys. The rationale here is that faulting workers
// will be reaped by the system, making it easy to determine which workers are
// active.
package registry

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/nats-io/nats.go"

	"go.hollow.sh/toolbox/events/pkg/kv"
)

var (
	registry nats.KeyValue

	RegistryName  = "active-workers"
	registryTTL   = 3 * time.Minute
	replicaCount  = 3
	kvDescription = "a list of active workers in the system"

	ErrRegistryUninitialized = errors.New("worker registry uninitialized")
)

// XXX: it's an error to call this without initializing the kv system
func InitializeActiveWorkerRegistry() error {
	return InitializeRegistryWithOptions(kv.WithReplicas(replicaCount),
		kv.WithDescription(kvDescription),
		kv.WithTTL(registryTTL),
	)
}

// XXX: You probably don't want the un-opinionated one, but it's here.
func InitializeRegistryWithOptions(opts ...kv.Option) error {
	if registry != nil {
		return nil
	}
	var err error
	registry, err = kv.CreateOrBindKVBucket(RegistryName, opts...)
	return err
}

func proofOfLife() ([]byte, error) {
	active := &activityRecord{
		LastActive: time.Now(),
	}
	return json.Marshal(active)
}

func RegisterWorker(id WorkerID) error {
	if registry == nil {
		return ErrRegistryUninitialized
	}
	active, err := proofOfLife()
	if err != nil {
		return err
	}
	rev, err := registry.Create(id.String(), active)
	if err == nil {
		id.updateVersion(rev)
	}
	return err
}

func WorkerCheckin(id WorkerID) error {
	if registry == nil {
		return ErrRegistryUninitialized
	}
	active, err := proofOfLife()
	if err != nil {
		return err
	}
	rev, err := registry.Update(id.String(), active, id.version())
	if err == nil {
		id.updateVersion(rev)
	}
	return err
}

func DeregisterWorker(id WorkerID) error {
	if registry == nil {
		return ErrRegistryUninitialized
	}
	return registry.Delete(id.String())
}
