package notify

import (
	"context"

	"gitlab.eclipse.org/eclipse/xfsc/tsa/policy/internal/clients/event"
)

type Client interface {
	Send(ctx context.Context, data *event.Data) error
}

type Notify struct {
	client Client
}

func New(client Client) *Notify {
	return &Notify{client: client}
}

func (n *Notify) PolicyDataChange(ctx context.Context, data *event.Data) error {
	err := n.client.Send(ctx, data)
	if err != nil {
		return err
	}
	return nil
}
