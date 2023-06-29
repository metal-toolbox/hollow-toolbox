// Package events provides types and methods to interact with a messaging stream broker.
package events

import (
	"context"
)

type (
	// ResourceType is the kind of the object included the message.
	ResourceType string

	// EventType is a type identifying the Event kind that has occurred on an object.
	EventType string

	// StreamParameters is the configuration for the Stream broker, the interface
	// is type asserted by the stream broker implementation.
	StreamParameters interface{}
)

const (
	// Create action kind identifies objects that were created.
	Create EventType = "create"

	// Update action kind identifies objects that were updated.
	Update EventType = "update"

	// Delete action kind identifies objects that were removed.
	Delete EventType = "delete"
)

// Stream provides methods to interact with the event stream.
type Stream interface {
	// Open sets up the stream connection.
	Open() error

	// Publish publishes the message to the message broker.
	Publish(ctx context.Context, subject string, msg []byte) error

	// Subscribe subscribes to one or more subjects on the stream returning a message channel for subscribers to read from.
	Subscribe(ctx context.Context) (MsgCh, error)

	// PullMsg pulls upto batch count of messages from the stream through the pull based subscription.
	PullMsg(ctx context.Context, batch int) ([]Message, error)

	// Closes the connection to the stream, along with unsubscribing any subscriptions.
	Close() error
}

// MsgCh is a channel over which messages arrive when subscribed.
type MsgCh chan Message

// Message interface defines the methods available on the messages received on the stream.
//
// These methods are to be implemented by the stream broker for its messages.
type Message interface {
	// Ack the message as processed on the stream.
	Ack() error

	// Nak the message as not processed on the stream.
	Nak() error

	// Term signals to the broker that the message processing has failed and the message
	// must not be redelivered.
	Term() error

	// InProgress resets the redelivery timer for the message on the stream
	// to indicate the message is being worked on.
	InProgress() error

	// Subject returns the message subject.
	Subject() string

	// Data returns the data contained in the message.
	Data() []byte

	// ExtractOtelTraceContext returns a context populated with the parent trace if any.
	ExtractOtelTraceContext(ctx context.Context) context.Context
}

// NewStream returns a Stream implementation.
func NewStream(parameters StreamParameters) (Stream, error) {
	return NewNatsBroker(parameters)
}
