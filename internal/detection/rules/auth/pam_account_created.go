package rule

import (
	"fmt"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// AccountCreatedRule fires on every new local user account creation.
// Creating accounts is a common persistence technique — every instance warrants review.
type AccountCreatedRule struct{}

func NewAccountCreatedRule() *AccountCreatedRule {
	return &AccountCreatedRule{}
}

func (r *AccountCreatedRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:  "auth",
		Program:    "useradd",
		EventTypes: []string{"ACCOUNT_CREATED"},
	}
}

func (r *AccountCreatedRule) Evaluate(event *model.NormalizedEvent, _ *context.DetectionContext) []*model.Alert {
	if event.Username == "" {
		return nil
	}

	return []*model.Alert{
		model.NewAlert(
			"New Account Created",
			model.SeverityHigh,
			"account",
			fmt.Sprintf("New local user account created: %s", event.Username),
			event,
			1,
		),
	}
}
