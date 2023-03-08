package events

import (
	"time"

	"github.com/nats-io/nats.go"
	"github.com/pkg/errors"
	"golang.org/x/exp/slices"
)

const (
	// nats server connection timeout
	connectTimeout = 100 * time.Millisecond

	// reconnect jitter
	reconnectJitter = 10 * time.Second

	// reconnect wait
	reconnectWait = 10 * time.Second

	// subscription callback timeout
	subscriptionCallbackTimeout = 5 * time.Second

	// Nak message with delay
	nakDelay = 5 * time.Minute

	// consumer defaults
	consumerAckWait       = 5 * time.Minute
	consumerMaxAckPending = 100
	consumerDeliverPolicy = nats.DeliverAllPolicy
)

// NatsOptions holds the configuration parameters to setup NATS Jetstream.
type NatsOptions struct {
	// URL is the NATS server URL
	URL string `mapstructure:"url"`

	// AppName is the name of the application connecting to the
	// NATS stream, this parameter is used to open the NATS connection
	// and bind as a durable consumer.
	AppName string `mapstructure:"app_name"`

	// NATS stream user, when no creds file is provided.
	StreamUser string `mapstructure:"stream_user"`

	// NATS stream pass, when no creds file is provided.
	StreamPass string `mapstructure:"stream_pass"`

	// NATS creds file
	CredsFile string `mapstructure:"creds_file"`

	// The subject prefix when publishing a message.
	PublisherSubjectPrefix string `mapstructure:"publisher_subject_prefix"`

	// URN Namespace to include in the published messages.
	StreamURNNamespace string `mapstructure:"stream_urn_ns"`

	// SubscribeSubjects when defined will result in the event broker subscribing to given streams.
	SubscribeSubjects []string `mapstructure:"subscribe_subjects"`

	// NATS connection timeout
	ConnectTimeout time.Duration `mapstructure:"connect_timeout"`

	// Setting Consumer parameters will cause a NATS consumer to be added.
	Consumer *NatsConsumerOptions `mapstructure:"consumer"`

	// Setting Stream parameters will cause a NATS stream to be added.
	Stream *NatsStreamOptions `mapstructure:"stream"`
}

// NatsConsumerOptions is the parameters for the NATS consumer configuration.
//
// Note: Nats consumers are views into the stream, multiple subscribers may bind on a consumer.
type NatsConsumerOptions struct {
	// Pull indicates this is a pull based subscriber
	Pull bool `mapstructure:"pull"`

	// Sets the durable consumer name
	Name string `mapstructure:"name"`

	// Sets the queue group for this consumer
	QueueGroup string `mapstructure:"queue_group"`

	AckWait time.Duration `mapstructure:"ack_wait"`

	MaxAckPending int `mapstructure:"max_ack_pending"`

	// Setting the FilterSubject turns this consumer into a push based consumer,
	// With no filter subject, the consumer is a pull based consumer.
	//
	// Although if the stream is a WorkQueue stream, then this must be set
	// and should be unique between consumers on the stream.
	FilterSubject string `mapstructure:"filter_subject"`

	// Subscribe to these subjects through this consumer.
	SubscribeSubjects []string `mapstructure:"subscribe_subjects"`
}

// NatsStreamOptions are parameters to setup a NATS stream.
type NatsStreamOptions struct {
	// Name for the stream
	Name string `mapstructure:"name"`

	// Subjects allowed to publish on the stream
	Subjects []string `mapstructure:"subjects"`

	// Acknowledgements required for each msg
	//
	// https://docs.nats.io/using-nats/developer/develop_jetstream/model_deep_dive#acknowledgement-models
	Acknowledgements bool `mapstructure:"acknowledgements"`

	// DuplicateWindow, messages containing the same message ID will be
	// deduplicated in this time window.
	//
	// https://docs.nats.io/using-nats/developer/develop_jetstream/model_deep_dive#message-deduplication
	DuplicateWindow time.Duration `mapstructure:"duplicate_window"`

	// Retention is the message eviction criteria
	//
	// https://docs.nats.io/using-nats/developer/develop_jetstream/model_deep_dive#stream-limits-retention-and-policy
	Retention string `mapstructure:"retention"`
}

func (o *NatsOptions) validate() error {
	if o.AppName == "" {
		return errors.Wrap(ErrNatsConfig, "AppName not defined, required to setup durable consumers")
	}

	if o.URL == "" {
		return errors.Wrap(ErrNatsConfig, "server URL not defined")
	}

	if o.CredsFile == "" && o.StreamUser == "" {
		return errors.Wrap(ErrNatsConfig, "either a creds file or a stream user, password is required")
	}

	if o.StreamUser != "" && o.StreamPass == "" {
		return errors.Wrap(ErrNatsConfig, "a stream user requires a password")
	}

	if o.ConnectTimeout == 0 {
		o.ConnectTimeout = connectTimeout
	}

	if o.Stream != nil {
		if err := o.validateStreamParameters(); err != nil {
			return err
		}
	}

	if o.Consumer != nil {
		if err := o.validateConsumerParameters(); err != nil {
			return err
		}
	}

	return nil
}

func (o *NatsOptions) validateStreamParameters() error {
	if o.Stream.Retention == "" {
		o.Stream.Retention = "limits"
	}

	if !slices.Contains([]string{"workQueue", "limits", "interest"}, o.Stream.Retention) {
		return errors.Wrap(ErrNatsConfig, "Stream parameters require a valid Retention")
	}

	if o.Stream.Name == "" {
		return errors.Wrap(ErrNatsConfig, "stream parameters require a Name")
	}

	if len(o.Stream.Subjects) == 0 {
		return errors.Wrap(ErrNatsConn, "stream parameters require one or more Subjects to associate with the stream")
	}

	return nil
}

func (o *NatsOptions) validateConsumerParameters() error {
	if o.Consumer.AckWait == 0 {
		o.Consumer.AckWait = consumerAckWait
	}

	if o.Consumer.MaxAckPending == 0 {
		o.Consumer.MaxAckPending = consumerMaxAckPending
	}

	return nil
}
