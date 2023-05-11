//nolint:all // linting test code is a waste of time
package registry

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.hollow.sh/toolbox/events"
	kvTest "go.hollow.sh/toolbox/events/internal/test"
)

func TestAppLifecycle(t *testing.T) {
	t.Parallel()
	id := GetID("testApp")

	// ops on uninitialized registry: I mean GIGO, right?
	err := RegisterController(id)
	require.Error(t, err)
	require.Equal(t, ErrRegistryUninitialized, err)
	err = ControllerCheckin(id)
	require.Error(t, err)
	require.Equal(t, ErrRegistryUninitialized, err)
	err = DeregisterController(id)
	require.Error(t, err)
	require.Equal(t, ErrRegistryUninitialized, err)

	//OK, now let's get serious
	srv := kvTest.StartJetStreamServer(t)
	defer kvTest.ShutdownJetStream(t, srv)
	nc, _ := kvTest.JetStreamContext(t, srv)
	evJS := events.NewJetstreamFromConn(nc)
	defer evJS.Close()

	err = InitializeRegistryWithOptions(evJS) // yes, this is explcitly nil options
	require.NoError(t, err)

	err = InitializeActiveControllerRegistry(evJS)
	require.Error(t, err)
	require.Equal(t, ErrRegistryPreviouslyInitialized, err)

	err = RegisterController(id)
	require.NoError(t, err)
	err = ControllerCheckin(id)
	require.NoError(t, err)
	err = DeregisterController(id)
	require.NoError(t, err)
}
