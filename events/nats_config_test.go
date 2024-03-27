package events

import (
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestNatsOptions_ValidatePrereqs(t *testing.T) {
	type fields struct {
		URL            string
		AppName        string
		StreamUser     string
		StreamPass     string
		CredsFile      string
		ConnectTimeout time.Duration
	}

	tests := []struct {
		name           string
		fields         fields
		errorContains  string
		wantParameters *NatsOptions
	}{
		{
			"AppName required",
			fields{},
			"AppName not defined",
			nil,
		},
		{
			"NATS URL required",
			fields{AppName: "foo"},
			"server URL not defined",
			nil,
		},
		{
			"Creds file or Stream user and password credentials required",
			fields{AppName: "foo", URL: "nats://nats:4222"},
			"creds file",
			nil,
		},
		{
			"Stream user requires a password",
			fields{AppName: "foo", URL: "nats://nats:4222", StreamUser: "foo"},
			"requires a password",
			nil,
		},
		{
			"Default connect timeout is set",
			fields{AppName: "foo", URL: "nats://nats:4222", StreamUser: "foo", StreamPass: "bar", ConnectTimeout: 200 * time.Millisecond},
			"",
			&NatsOptions{AppName: "foo", URL: "nats://nats:4222", StreamUser: "foo", StreamPass: "bar", ConnectTimeout: 200 * time.Millisecond},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &NatsOptions{
				URL:            tt.fields.URL,
				AppName:        tt.fields.AppName,
				StreamUser:     tt.fields.StreamUser,
				StreamPass:     tt.fields.StreamPass,
				CredsFile:      tt.fields.CredsFile,
				ConnectTimeout: tt.fields.ConnectTimeout,
			}

			err := o.validatePrereqs()
			if tt.errorContains != "" {
				assert.True(t, errors.Is(err, ErrNatsConfig))
				assert.ErrorContains(t, err, tt.errorContains)
			}

			if tt.wantParameters != nil {
				assert.Equal(t, tt.wantParameters, o)
			}
		})
	}
}

func TestNatsStreamOptions_Validate(t *testing.T) {
	type fields struct {
		Name             string
		Subjects         []string
		Acknowledgements bool
		DuplicateWindow  time.Duration
		Retention        string
	}

	tests := []struct {
		name           string
		fields         fields
		errorContains  string
		wantParameters *NatsStreamOptions
	}{
		{
			"Invalid retention parameter",
			fields{Retention: "foobar"},
			"require a valid Retention",
			nil,
		},
		{
			"Stream Name required",
			fields{},
			"require a Name",
			nil,
		},
		{
			"Subjects to associate with stream required",
			fields{Retention: "limits", Name: "hollow"},
			"require one or more Subjects",
			nil,
		},
		{
			"Default retention set",
			fields{Name: "hollow", Subjects: []string{"foo.bar"}},
			"",
			&NatsStreamOptions{Name: "hollow", Subjects: []string{"foo.bar"}, Retention: "limits"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &NatsStreamOptions{
				Name:             tt.fields.Name,
				Subjects:         tt.fields.Subjects,
				Acknowledgements: tt.fields.Acknowledgements,
				DuplicateWindow:  tt.fields.DuplicateWindow,
				Retention:        tt.fields.Retention,
			}

			err := s.validate()
			if tt.errorContains != "" {
				assert.True(t, errors.Is(err, ErrNatsConfig))
				assert.ErrorContains(t, err, tt.errorContains)
			}

			if tt.wantParameters != nil {
				assert.Equal(t, tt.wantParameters, s)
			}
		})
	}
}

func TestNatsConsumerOptions_Validate(t *testing.T) {
	type fields struct {
		Pull              bool
		Name              string
		QueueGroup        string
		AckWait           time.Duration
		MaxAckPending     int
		FilterSubject     string
		SubscribeSubjects []string
	}

	tests := []struct {
		name          string
		errorContains string
		fields        *fields
		want          *NatsConsumerOptions
	}{
		{
			"Consumer Name required",
			"require a Name",
			&fields{},
			nil,
		},
		{
			"Defaults set",
			"",
			&fields{Name: "foo"},
			&NatsConsumerOptions{
				Name:          "foo",
				AckWait:       consumerAckWait,
				MaxAckPending: consumerMaxAckPending,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &NatsConsumerOptions{Name: tt.fields.Name}

			err := c.validate()
			if tt.errorContains != "" {
				assert.True(t, errors.Is(err, ErrNatsConfig))
				assert.ErrorContains(t, err, tt.errorContains)
			}

			if tt.want != nil {
				assert.Equal(t, tt.want, c)
			}
		})
	}
}
