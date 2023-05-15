//nolint:all
package events

import (
	"testing"

	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/require"
)

type bogusMsg struct{}

func (_ *bogusMsg) Ack() error {
	return nil
}

func (_ *bogusMsg) Nak() error {
	return nil
}

func (_ *bogusMsg) InProgress() error {
	return nil
}

func (_ *bogusMsg) Term() error {
	return nil
}

func (_ *bogusMsg) Subject() string {
	return "bogus"
}

func (_ *bogusMsg) Data() []byte {
	return nil
}

func TestConversions(t *testing.T) {
	nm := &natsMsg{
		msg: nats.NewMsg("some.subject"),
	}
	b := &bogusMsg{}

	m1 := Message(nm)
	m2 := Message(b)

	m, err := AsNatsMsg(m1)
	require.NoError(t, err, "good conversion failed")
	require.Equal(t, nm.msg, m)
	_, err = AsNatsMsg(m2)
	require.Error(t, err, "bad conversion returns no error")
	require.NotPanics(t, func() { MustNatsMsg(m1) }, "good conversion panicked")
	require.Panics(t, func() { MustNatsMsg(m2) }, "bad conversion did not panic")
}
