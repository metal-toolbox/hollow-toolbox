package registry

import (
	"testing"

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
}
