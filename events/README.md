# Events

Package events provides an interface and methods to interact with an events stream broker.

The package provides methods to serialize, deserialize data sent on the stream
as a [pubsubx.Message](https://github.com/infratographer/x/tree/main/pubsubx) along with methods
to parse the message URN through [urnx](https://github.com/infratographer/x/tree/main/urnx).


### Connect to a NATS Jetstream to publish messages.

Example below sets up a NATS stream broker with the parameters provided,
The stream, consumer and subscription(s) are initialized when defined, based on the configuration.

```go
	options := events.NatsOptions{
		AppName:                "foo",
		URL:                    "nats://nats:4222",
		StreamUser:             viper.GetString("nats.stream.user"),
		StreamPass:             viper.GetString("nats.stream.pass"),
		CredsFile:              viper.GetString("nats.creds.file"),
		...

		// Defining a stream will result in the stream being added if not present.
		Stream: &events.NatsStreamOptions{
			// Name of the stream to be created.
			Name:     viper.GetString("nats.stream.name"),

			// Subjects associated with the stream.
			Subjects: viper.GetStringSlice("nats.stream.subjects"),
		},

		// Defining a consumer will result in the consumer being added if not present.
		Consumer: &events.NatsConsumerOptions{
			// Pull indicates this is a pull based stream, subcriptions to it will be pull based.
			Pull: viper.GetBool("nats.stream.consumer.pull")

			// Sets the durable consumer name, by setting a durable consumer name
			// the consumer is not epheremal and removed once there are no subscribers.
			Name: viper.GetString("nats.stream.consumer.name")

			....
		}
	}

	// initialize broker - validates the configuration and returns a Stream
	stream, err := events.NewStream(natsOptions(appName, streamURL))
	if err != nil {
		panic(err)
	}

	// Open connection - sets up required streams, consumers.
	if err := stream.Open(); err != nil {
		panic(err)
	}


    // publish asynchronously to subscribed consumer.
	if err := stream.PublishAsyncWithContext(ctx, resourceTypeServer, eventTypeCreate, uuid.New(), &Server{}); err != nil {
		panic(err)
	}


	// subscribe to one or more consumers, this returns a single channel.
	eventsCh, err := o.streamBroker.Subscribe(ctx)
	if err != nil {
		o.logger.Fatal(err)
	}

	for _, msg := range {
		// unpacks the data as a *pubsubx.Message
		data, err := msg.Data()
		if err != nil {
			panic(err)
		}

		// parse and retrieve the Subject URN
		urn, err := msg.SubjectURN(data)
		if err != nil {
			panic(err)
		}

		// ack the message
		if err := msg.Ack(); err != nil {
			panic(err)
		}
	}
```

## Implementations

TODO(joel) : Link to implementations of this library.
