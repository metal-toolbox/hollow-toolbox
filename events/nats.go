//nolint:wsl
package events

import (
	"context"
	"log"
	"reflect"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/nats-io/nats.go"
	"github.com/pkg/errors"
)

var (
	// ErrNatsConfig is returned when the conf
	ErrNatsConfig = errors.New("error in NATs Jetstream configuration")

	// ErrNatsConn is returned when an error occurs in connecting to NATS.
	ErrNatsConn = errors.New("error opening nats connection")

	// ErrNatsJetstream is returned when an error occurs in setting up the NATS Jetstream context.
	ErrNatsJetstream = errors.New("error in NATS Jetstream")

	// ErrNatsJetstreamAddStream os returned when an attempt to add a NATS Jetstream fails.
	ErrNatsJetstreamAddStream = errors.New("error adding stream to NATS Jetstream")

	// ErrNatsJetstreamAddConsumer is returned when theres an error adding a consumer to the NATS Jetstream.
	ErrNatsJetstreamAddConsumer = errors.New("error adding consumer on NATS Jetstream")

	// ErrNatsMsgPull is returned when theres and error pulling a message from a NATS Jetstream.
	ErrNatsMsgPull = errors.New("error fetching message from NATS Jetstream")

	// ErrSubscription is returned when an error in the consumer subscription occurs.
	ErrSubscription = errors.New("error subscribing to stream")
)

// NatsJetstream wraps the NATs JetStream connector to implement the Stream interface.
type NatsJetstream struct {
	jsctx         nats.JetStreamContext
	conn          *nats.Conn
	parameters    *NatsOptions
	subscriptions []*nats.Subscription
	subscriberCh  MsgCh
}

func (n *NatsJetstream) streamReplicas() int {
	if n.parameters.Stream.Replicas == 0 {
		return 1
	}
	return n.parameters.Stream.Replicas
}

// Add some conversions for functions/APIs that expect NATS primitive types. This allows consumers of
// NatsJetsream to convert easily to the types they need, without exporting the members or coercing
// and direct clients/holders of NatsJetstream to do this conversion.
// AsNatsConnection exposes the otherwise private NATS connection pointer
func AsNatsConnection(n *NatsJetstream) *nats.Conn {
	return n.conn
}

// AsNatsJetstreamContext exposes the otherwise private NATS JetStreamContext
func AsNatsJetStreamContext(n *NatsJetstream) nats.JetStreamContext {
	return n.jsctx
}

// NewNatsBroker validates the given stream broker parameters and returns a stream broker implementation.
func NewNatsBroker(params StreamParameters) (*NatsJetstream, error) {
	parameters, valid := params.(NatsOptions)
	if !valid {
		return nil, errors.Wrap(
			ErrNatsConfig,
			"expected parameters of type NatsOptions{}, got: "+reflect.TypeOf(parameters).String(),
		)
	}

	if err := parameters.validate(); err != nil {
		return nil, err
	}

	return &NatsJetstream{parameters: &parameters}, nil
}

// NewJetstreamFromConn takes an already established NATS connection pointer and returns a NatsJetstream pointer
func NewJetstreamFromConn(c *nats.Conn) *NatsJetstream {
	// JetStream() only returns an error if you call it with incompatible options. It is *not*
	// a guarantee that c has JetStream enabled.
	js, _ := c.JetStream()
	return &NatsJetstream{
		conn:  c,
		jsctx: js,
	}
}

// Open connects to the NATS Jetstream.
func (n *NatsJetstream) Open() error {
	if n.conn != nil {
		return errors.Wrap(ErrNatsConn, "NATS connection is already established")
	}

	if n.parameters == nil {
		return errors.Wrap(ErrNatsConfig, "NATS config parameters not defined")
	}

	opts := []nats.Option{
		nats.Name(n.parameters.AppName),
		nats.Timeout(n.parameters.ConnectTimeout),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(reconnectWait),
		nats.ReconnectJitter(reconnectJitter, reconnectJitter),
	}

	if n.parameters.StreamUser != "" {
		opts = append(opts, nats.UserInfo(n.parameters.StreamUser, n.parameters.StreamPass))
	} else {
		opts = append(opts, nats.UserCredentials(n.parameters.CredsFile))
	}

	conn, err := nats.Connect(n.parameters.URL, opts...)
	if err != nil {
		return errors.Wrap(ErrNatsConn, err.Error())
	}

	n.conn = conn

	// setup the channel for subscribers to read messages from.
	n.subscriberCh = make(MsgCh)

	// setup Jetstream and consumer
	return n.setup()
}

func (n *NatsJetstream) setup() error {
	js, err := n.conn.JetStream()
	if err != nil {
		return errors.Wrap(ErrNatsJetstream, err.Error())
	}

	n.jsctx = js

	if n.parameters.Stream != nil {
		if err := n.addStream(); err != nil {
			return err
		}
	}

	if n.parameters.Consumer != nil {
		if err := n.addConsumer(); err != nil {
			return err
		}
	}

	return nil
}

func (n *NatsJetstream) addStream() error {
	if n.jsctx == nil {
		return errors.Wrap(ErrNatsJetstreamAddStream, "Jetstream context is not setup")
	}

	// check stream isn't already present
	for name := range n.jsctx.StreamNames() {
		if name == n.parameters.Stream.Name {
			return nil
		}
	}

	var retention nats.RetentionPolicy

	switch n.parameters.Stream.Retention {
	case "workQueue":
		retention = nats.WorkQueuePolicy
	case "limits":
		retention = nats.LimitsPolicy
	case "interest":
		retention = nats.InterestPolicy
	default:
		return errors.Wrap(ErrNatsConfig, "unknown retention policy defined: "+n.parameters.Stream.Retention)
	}

	_, err := n.jsctx.AddStream(
		&nats.StreamConfig{
			Name:      n.parameters.Stream.Name,
			Subjects:  n.parameters.Stream.Subjects,
			Retention: retention,
			Replicas:  n.streamReplicas(),
		},
	)

	if err != nil {
		return errors.Wrap(ErrNatsJetstreamAddStream, err.Error())
	}

	return nil
}

// AddConsumer adds a consumer for a stream
//
// Consumers are view into a NATs Jetstream
// multiple applications may bind to a consumer.
func (n *NatsJetstream) addConsumer() error {
	if n.jsctx == nil {
		return errors.Wrap(ErrNatsJetstreamAddConsumer, "Jetstream context is not setup")
	}

	// lookup consumers in stream before attempting to add consumer
	for name := range n.jsctx.ConsumerNames(n.parameters.Consumer.Name) {
		if name == n.parameters.Consumer.Name {
			return nil
		}
	}

	// https://pkg.go.dev/github.com/nats-io/nats.go#ConsumerConfig
	cfg := &nats.ConsumerConfig{
		Durable:       n.parameters.Consumer.Name,
		MaxDeliver:    -1,
		AckPolicy:     nats.AckExplicitPolicy,
		AckWait:       n.parameters.Consumer.AckWait,
		MaxAckPending: n.parameters.Consumer.MaxAckPending,
		DeliverPolicy: nats.DeliverAllPolicy,
		DeliverGroup:  n.parameters.Consumer.QueueGroup,
		FilterSubject: n.parameters.Consumer.FilterSubject,
	}

	if _, err := n.jsctx.AddConsumer(n.parameters.Stream.Name, cfg); err != nil {
		return errors.Wrap(ErrNatsJetstreamAddConsumer, err.Error())
	}

	return nil
}

// Publish publishes an event onto the NATS Jetstream. The caller is responsible for message
// addressing and data serialization. NOTE: The subject passed here will be prepended with any
// configured PublisherSubjectPrefix.
func (n *NatsJetstream) Publish(_ context.Context, subjectSuffix string, data []byte) error {
	if n.jsctx == nil {
		return errors.Wrap(ErrNatsJetstreamAddConsumer, "Jetstream context is not setup")
	}

	// retry publishing for a while
	options := []nats.PubOpt{
		nats.RetryAttempts(-1),
	}

	fullSubject := strings.Join(
		[]string{
			n.parameters.PublisherSubjectPrefix,
			subjectSuffix,
		}, ".")

	_, err := n.jsctx.Publish(fullSubject, data, options...)
	return err
}

// Subscribe to all configured SubscribeSubjects
func (n *NatsJetstream) Subscribe(ctx context.Context) (MsgCh, error) {
	if n.jsctx == nil {
		return nil, errors.Wrap(ErrNatsJetstreamAddConsumer, "Jetstream context is not setup")
	}

	// Subscribe as a pull based subscriber
	if n.parameters.Consumer != nil && n.parameters.Consumer.Pull {
		if err := n.subscribeAsPull(ctx); err != nil {
			return nil, err
		}
	}

	// regular Async subscription
	for _, subject := range n.parameters.SubscribeSubjects {
		subscription, err := n.jsctx.Subscribe(subject, n.subscriptionCallback, nats.Durable(n.parameters.AppName))
		if err != nil {
			return nil, errors.Wrap(ErrSubscription, err.Error()+": "+subject)
		}

		n.subscriptions = append(n.subscriptions, subscription)
	}

	return n.subscriberCh, nil
}

// subscribeAsPull sets up the pull subscription
func (n *NatsJetstream) subscribeAsPull(_ context.Context) error {
	if n.jsctx == nil {
		return errors.Wrap(ErrNatsJetstreamAddConsumer, "Jetstream context is not setup")
	}

	for _, subject := range n.parameters.Consumer.SubscribeSubjects {
		subscription, err := n.jsctx.PullSubscribe(subject, n.parameters.Consumer.Name,
			nats.BindStream(n.parameters.Stream.Name))
		if err != nil {
			log.Printf("PullSubscribe with subject=%s, durable=%s, stream=%s => %v", subject, n.parameters.AppName,
				n.parameters.Stream.Name, err)
			return errors.Wrap(ErrSubscription, err.Error()+": "+subject)
		}

		n.subscriptions = append(n.subscriptions, subscription)
	}

	return nil
}

// XXX: the ergonomics here are weird, because we're handling potentially multiple subscriptions
// in a single call, and an error on any single retrieve just aborts the group operation.

// PullMsg pulls up to the batch count of messages from each pull-based subscription to
// subjects on the stream.
func (n *NatsJetstream) PullMsg(_ context.Context, batch int) ([]Message, error) {
	if n.jsctx == nil {
		return nil, errors.Wrap(ErrNatsJetstreamAddConsumer, "Jetstream context is not setup")
	}

	var hasPullSubscription bool
	var msgs []Message

	for _, subscription := range n.subscriptions {
		if subscription.Type() != nats.PullSubscription {
			continue
		}

		hasPullSubscription = true

		subMsgs, err := subscription.Fetch(batch)
		if err != nil {
			return nil, errors.Wrap(ErrNatsMsgPull, err.Error())
		}
		msgs = append(msgs, msgIfFromNats(subMsgs...)...)
	}

	if !hasPullSubscription {
		return nil, errors.Wrap(ErrNatsMsgPull, "no pull subscriptions to fetch from")
	}

	return msgs, nil
}

func (n *NatsJetstream) subscriptionCallback(msg *nats.Msg) {
	select {
	case <-time.After(subscriptionCallbackTimeout):
		_ = msg.NakWithDelay(nakDelay)
	case n.subscriberCh <- &natsMsg{msg: msg}:
	}
}

// Close drains any subscriptions and closes the NATS Jetstream connection.
func (n *NatsJetstream) Close() error {
	var errs error

	for _, subscription := range n.subscriptions {
		if err := subscription.Drain(); err != nil {
			errs = multierror.Append(err, err)
		}
	}

	if n.conn != nil {
		n.conn.Close()
	}

	return errs
}
