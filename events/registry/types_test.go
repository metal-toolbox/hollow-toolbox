//nolint:all // it's a test
package registry

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestWorkerID(t *testing.T) {
	// Property 1: an id can be obtained
	id := GetID("myAppName")
	require.NotNil(t, id)
	// Property 2: even with identical input, unique ids are generated
	id2 := GetID("myAppName")
	require.NotNil(t, id2)
	require.NotEqual(t, id.String(), id2.String())

	idStr := id.String()

	reconstituted, err := ControllerIDFromString(idStr)
	require.NoError(t, err)
	require.Equal(t, id.(*workerUUID).appName, reconstituted.(*workerUUID).appName)
	require.Equal(t, id.(*workerUUID).uuid, reconstituted.(*workerUUID).uuid)

	_, err = ControllerIDFromString(uuid.New().String())
	require.ErrorIs(t, err, ErrBadFormat, "no slash in name")

	_, err = ControllerIDFromString("app-name/bogus")
	require.ErrorIs(t, err, ErrBadFormat, "bogus uuid")
}
