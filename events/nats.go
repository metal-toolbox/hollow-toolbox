package events

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/nats-io/nats.go"
	"github.com/pkg/errors"
	"go.infratographer.com/x/pubsubx"
	"go.infratographer.com/x/urnx"
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

// Open connects to the NATS Jetstream.
func (n *NatsJetstream) Open() error {
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
	for name := range n.jsctx.ConsumerNames(n.parameters.Stream.Name) {
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

// PublishAsyncWithContext publishes an event onto the NATS Jetstream.
func (n *NatsJetstream) PublishAsyncWithContext(_ context.Context, resType ResourceType, eventType EventType, objID string, obj interface{}) error {
	if n.jsctx == nil {
		return errors.Wrap(ErrNatsJetstreamAddConsumer, "Jetstream context is not setup")
	}

	msg := newEventStreamMessage(n.parameters.AppName, n.parameters.StreamURNNamespace, eventType, resType, objID)
	msg.AdditionalData = map[string]interface{}{"data": obj}
	msg.EventType = string(eventType)

	msgb, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	// retry publishing for a while
	options := []nats.PubOpt{
		nats.RetryAttempts(-1),
	}

	subject := fmt.Sprintf("%s.%s.%s", n.parameters.PublisherSubjectPrefix, resType, eventType)
	if _, err := n.jsctx.PublishAsync(subject, msgb, options...); err != nil {
		return err
	}

	return nil
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
		subscription, err := n.jsctx.PullSubscribe(subject, n.parameters.AppName, nats.BindStream(n.parameters.Stream.Name))
		if err != nil {
			return errors.Wrap(ErrSubscription, err.Error()+": "+subject)
		}

		n.subscriptions = append(n.subscriptions, subscription)
	}

	return nil
}

// PullMsg pulls upto batch count of messages from the stream through the pull based subscription.
func (n *NatsJetstream) PullMsg(_ context.Context, batch int) ([]Message, error) {
	if n.jsctx == nil {
		return nil, errors.Wrap(ErrNatsJetstreamAddConsumer, "Jetstream context is not setup")
	}

	msgs := []Message{}

	var hasPullSubscription bool

	for _, subscription := range n.subscriptions {
		if subscription.Type() != nats.PullSubscription {
			continue
		}

		hasPullSubscription = true

		natsMsgs, err := subscription.Fetch(batch)
		if err != nil {
			return nil, errors.Wrap(ErrNatsMsgPull, err.Error())
		}

		for _, msg := range natsMsgs {
			msgs = append(msgs, &NatsMsg{natsMsg: msg})
		}
	}

	if !hasPullSubscription {
		return nil, errors.Wrap(ErrNatsMsgPull, "no pull subscriptions to fetch from")
	}

	return msgs, nil
}

func (n *NatsJetstream) subscriptionCallback(natsMsg *nats.Msg) {
	msg := &NatsMsg{natsMsg: natsMsg}

	select {
	case <-time.After(subscriptionCallbackTimeout):
		_ = natsMsg.NakWithDelay(nakDelay)
	case n.subscriberCh <- msg:
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

// NatsMsg implements the Stream Message interface
type NatsMsg struct {
	natsMsg *nats.Msg
	Payload json.RawMessage
}

// Ack notifies the stream the message has been processed.
func (m *NatsMsg) Ack() error {
	return m.natsMsg.Ack()
}

// Nak notifies the stream the message could not be processed and has to be redelivered.
func (m *NatsMsg) Nak() error {
	return m.natsMsg.Nak()
}

// InProgress resets the redelivery timer on the message and so notifying the stream
// its being processed.
func (m *NatsMsg) InProgress() error {
	return m.natsMsg.InProgress()
}

// Subject returns the subject on the message.
func (m *NatsMsg) Subject() string {
	return m.natsMsg.Subject
}

// Data serializes and returns the message as a *pubsubx.Message.
func (m *NatsMsg) Data() (*pubsubx.Message, error) {
	msg := &pubsubx.Message{}
	if err := json.Unmarshal(m.natsMsg.Data, msg); err != nil {
		return nil, err
	}

	return msg, nil
}

// SubjectURN returns the message subject URN.
func (m *NatsMsg) SubjectURN(msg *pubsubx.Message) (*urnx.URN, error) {
	return urnx.Parse(msg.SubjectURN)
}

// ActorURN returns the message actor URN.
func (m *NatsMsg) ActorURN(msg *pubsubx.Message) (*urnx.URN, error) {
	return urnx.Parse(msg.ActorURN)
}
