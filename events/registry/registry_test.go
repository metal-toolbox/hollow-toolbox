//nolint:all // linting test code is a waste of time
package registry

import (
	"testing"

	"github.com/stretchr/testify/require"

	kvTest "go.hollow.sh/toolbox/events/internal/test"
	"go.hollow.sh/toolbox/events/pkg/kv"
)

func TestAppLifecycle(t *testing.T) {
	t.Parallel()
	id := GetID("testApp")

	// ops on uninitialized registry: I mean GIGO, right?
	err := RegisterWorker(id)
	require.Error(t, err)
	require.Equal(t, ErrRegistryUninitialized, err)
	err = WorkerCheckin(id)
	require.Error(t, err)
	require.Equal(t, ErrRegistryUninitialized, err)
	err = DeregisterWorker(id)
	require.Error(t, err)
	require.Equal(t, ErrRegistryUninitialized, err)

	//OK, now let's get serious
	srv := kvTest.StartJetStreamServer(t)
	defer kvTest.ShutdownJetStream(t, srv)
	nc, js := kvTest.JetStreamContext(t, srv)
	defer nc.Close()
	kv.InitializeKV(js)
	err = InitializeRegistryWithOptions() // yes, this is explcitly nil options
	require.NoError(t, err)
	err = RegisterWorker(id)
	require.NoError(t, err)
	err = WorkerCheckin(id)
	require.NoError(t, err)
	err = DeregisterWorker(id)
	require.NoError(t, err)
}
