//nolint:all
package events

import (
	"context"
	"testing"

	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/require"

	natsTest "go.hollow.sh/toolbox/events/internal/test"
)

func TestJetstreamFromConn(t *testing.T) {
	t.Parallel()
	core := natsTest.StartCoreServer(t)
	defer func() {
		core.Shutdown()
		core.WaitForShutdown()
	}()

	jsSrv := natsTest.StartJetStreamServer(t)
	defer natsTest.ShutdownJetStream(t, jsSrv)

	jsConn, _ := natsTest.JetStreamContext(t, jsSrv)

	conn, err := nats.Connect(core.ClientURL())
	require.NoError(t, err, "error on initial connection to core test server")
	defer conn.Close()

	// XXX: you can successfuilly get a JetStreamContext from a non-JetStream-enabled server but
	// it's an error to actually use it. That's super annoying. An error is returned from
	// conn.JetStream() only when incompatible options are provided to the function.
	njs := NewJetstreamFromConn(conn)

	_, err = AsNatsJetStreamContext(njs).AccountInfo()
	require.Error(t, err, "expected an error trying to use JetStream functions on a core server")
	require.Equal(t, nats.ErrJetStreamNotEnabled, err, "unexpected error touching JetStream context from core server")

	njs = NewJetstreamFromConn(jsConn)
	_, err = AsNatsJetStreamContext(njs).AccountInfo()
	require.NoError(t, err, "unexpected error using JetStream")
	njs.Close()
}

func TestPublishAndSubscribe(t *testing.T) {
	jsSrv := natsTest.StartJetStreamServer(t)
	defer natsTest.ShutdownJetStream(t, jsSrv)

	jsConn, _ := natsTest.JetStreamContext(t, jsSrv)
	njs := NewJetstreamFromConn(jsConn)
	defer njs.Close()

	njs.parameters = &NatsOptions{
		AppName: "TestPublishAndSubscribe",
		Stream: &NatsStreamOptions{
			Name: "test_stream",
			Subjects: []string{
				"test",
			},
			Retention: "workQueue",
		},
		Consumer: &NatsConsumerOptions{
			Name: "test_consumer",
			Pull: true,
			SubscribeSubjects: []string{
				"test",
			},
			FilterSubject: "test",
		},
	}
	require.NoError(t, njs.addStream())
	require.NoError(t, njs.addConsumer())

	_, err := njs.Subscribe(context.TODO())
	require.NoError(t, err)

	payload := []byte("test data")
	require.NoError(t, njs.Publish(context.TODO(), "test", payload))

	msgs, err := njs.PullMsg(context.TODO(), 1)
	require.NoError(t, err)
	require.Equal(t, 1, len(msgs))
	require.Equal(t, payload, msgs[0].Data())
}
