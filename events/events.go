// Package events provides types and methods to interact with a messaging stream broker.
package events

import (
	"context"
	"fmt"
	"time"

	"go.infratographer.com/x/pubsubx"
	"go.infratographer.com/x/urnx"
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
	// urnFormatString is the format for the uniform resource name.
	//
	// The string is to be formatted as "urn:<namespace>:<ResourceType>:<object UUID>"
	urnFormatString = "urn:%s:%s:%s"

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

	// PublishWithContext publishes the message to the message broker in an async manner.
	PublishAsyncWithContext(ctx context.Context, resType ResourceType, eventType EventType, resID string, obj interface{}) error

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

	// InProgress resets the redelivery timer for the message on the stream
	// to indicate the message is being worked on.
	InProgress() error

	// Subject returns the message subject.
	Subject() string

	// Data returns the data contained in the message.
	Data() (*pubsubx.Message, error)

	// SubjectURN returns the message subject URN.
	SubjectURN(*pubsubx.Message) (*urnx.URN, error)

	// ActorURN returns the actor URN from the message.
	ActorURN(*pubsubx.Message) (*urnx.URN, error)
}

// NewStream returns a Stream implementation.
func NewStream(parameters StreamParameters) (Stream, error) {
	return NewNatsBroker(parameters)
}

func newURN(namespace string, resType ResourceType, objID string) string {
	return fmt.Sprintf(urnFormatString, namespace, resType, objID)
}

func newEventStreamMessage(appName, urnNamespace string, eventType EventType, resType ResourceType, objID string) *pubsubx.Message {
	return &pubsubx.Message{
		EventType:  string(eventType),
		ActorURN:   "", // To be filled in with the data from the client request JWT.
		SubjectURN: newURN(urnNamespace, resType, objID),
		Timestamp:  time.Now().UTC(),
		Source:     appName,
	}
}
