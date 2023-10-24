package notify

import (
	"context"
)

//go:generate counterfeiter . Events

type Events interface {
	Send(ctx context.Context, data any) error
}

type Notifier struct {
	events Events
}

type EventPolicyChange struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Group   string `json:"group"`
}

// New creates a policy change notifier for interested subscribers.
// It can notify for policy changes both via MessageQueue or Web hooks.
func New(events Events) *Notifier {
	return &Notifier{events: events}
}

// PolicyDataChange is called when the policies source code or data are updated
// in storage. The function will notify subscribers of the given changes.
func (n *Notifier) PolicyDataChange(ctx context.Context, event *EventPolicyChange) error {
	return n.events.Send(ctx, event)
}
