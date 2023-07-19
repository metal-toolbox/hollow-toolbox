//nolint:all
package events

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	traceSDK "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

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
				"pre.test",
			},
			Retention: "workQueue",
		},
		Consumer: &NatsConsumerOptions{
			Name: "test_consumer",
			Pull: true,
			SubscribeSubjects: []string{
				"pre.test",
			},
			FilterSubject: "pre.test",
		},
		PublisherSubjectPrefix: "pre",
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

	msgs, err = njs.PullMsg(context.TODO(), 1)
	require.Error(t, err)
	require.ErrorIs(t, err, nats.ErrTimeout)
}

func Test_addConsumer(t *testing.T) {
	jsSrv := natsTest.StartJetStreamServer(t)
	defer natsTest.ShutdownJetStream(t, jsSrv)

	jsConn, _ := natsTest.JetStreamContext(t, jsSrv)
	njs := NewJetstreamFromConn(jsConn)
	defer njs.Close()

	consumerCfg := &NatsConsumerOptions{
		Name:       "test_consumer",
		QueueGroup: "test",
		Pull:       true,
		SubscribeSubjects: []string{
			"pre.test",
		},
		FilterSubject: "pre.test",
		MaxAckPending: 10,
		AckWait:       600 * time.Second,
	}

	njs.parameters = &NatsOptions{
		AppName: "TestPublishAndSubscribe",
		Stream: &NatsStreamOptions{
			Name: "test_stream",
			Subjects: []string{
				"pre.test",
			},
			Retention: "workQueue",
		},
		Consumer:               consumerCfg,
		PublisherSubjectPrefix: "pre",
	}

	require.NoError(t, njs.addStream())

	// add config
	require.NoError(t, njs.addConsumer())

	consumerInfo, err := njs.jsctx.ConsumerInfo("test_stream", consumerCfg.Name)
	require.NoError(t, err)

	assert.Equal(t, consumerCfg.Name, consumerInfo.Name)
	assert.Equal(t, false, consumerInfo.PushBound)
	assert.Equal(t, consumerCfg.MaxAckPending, consumerInfo.Config.MaxAckPending)
	assert.Equal(t, -1, consumerInfo.Config.MaxDeliver)
	assert.Equal(t, nats.AckExplicitPolicy, consumerInfo.Config.AckPolicy)
	assert.Equal(t, consumerCfg.AckWait, consumerInfo.Config.AckWait)
	assert.Equal(t, nats.DeliverAllPolicy, consumerInfo.Config.DeliverPolicy)
	assert.Equal(t, consumerCfg.QueueGroup, consumerInfo.Config.DeliverGroup)
	assert.Equal(t, consumerCfg.FilterSubject, consumerInfo.Config.FilterSubject)

	// update config
	consumerCfg.MaxAckPending = 30
	require.NoError(t, njs.addConsumer())

	consumerInfo, err = njs.jsctx.ConsumerInfo("test_stream", consumerCfg.Name)
	require.NoError(t, err)

	assert.Equal(t, consumerCfg.MaxAckPending, consumerInfo.Config.MaxAckPending)
}

func TestInjectOtelTraceContext(t *testing.T) {
	// set the tracing propagator so its available for injection
	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}),
	)

	// setup a new trace provider
	ctx, span := traceSDK.NewTracerProvider().Tracer("testing").Start(context.Background(), "foo.bar")
	defer span.End()

	msg := nats.NewMsg("foo.bar")
	msg.Data = []byte(`hello`)

	injectOtelTraceContext(ctx, msg)

	assert.NotEmpty(t, msg.Header.Get("Traceparent"))
}

func TestExtractOtelTraceContext(t *testing.T) {
	// set the tracing propagator so its available for injection
	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}),
	)

	// setup a new trace provider
	ctx, span := traceSDK.NewTracerProvider().Tracer("testing").Start(context.Background(), "foo.bar")
	defer span.End()

	msg := nats.NewMsg("foo.bar")
	msg.Data = []byte(`hello`)

	// inject
	injectOtelTraceContext(ctx, msg)

	// msg header gets a trace parent added
	traceParent := msg.Header.Get("Traceparent")

	// wrap natsMsg to pass to extract method
	nm := &natsMsg{msg}

	ctxWithTrace := nm.ExtractOtelTraceContext(context.Background())
	got := trace.SpanFromContext(ctxWithTrace).SpanContext().TraceID().String()

	assert.Contains(t, traceParent, got)
}
