package notify_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"gitlab.eclipse.org/eclipse/xfsc/tsa/policy/internal/notify"
	"gitlab.eclipse.org/eclipse/xfsc/tsa/policy/internal/notify/notifyfakes"
)

func TestNotify_PolicyDataChange(t *testing.T) {
	tests := []struct {
		name              string
		events            notify.Events
		eventPolicyChange *notify.EventPolicyChange

		errText string
	}{
		{
			name:              "error when sending event",
			eventPolicyChange: &notify.EventPolicyChange{Name: "exampleName", Version: "exampleVersion", Group: "exampleGroup"},
			events: &notifyfakes.FakeEvents{SendStub: func(ctx context.Context, a any) error {
				return fmt.Errorf("some error")
			}},

			errText: "some error",
		},

		{
			name:              "sending event is successful",
			eventPolicyChange: &notify.EventPolicyChange{Name: "exampleName", Version: "exampleVersion", Group: "exampleGroup"},
			events: &notifyfakes.FakeEvents{SendStub: func(ctx context.Context, a any) error {
				return nil
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			notifier := notify.New(test.events)
			err := notifier.PolicyDataChange(context.Background(), test.eventPolicyChange)
			if test.errText != "" {
				assert.ErrorContains(t, err, test.errText)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
