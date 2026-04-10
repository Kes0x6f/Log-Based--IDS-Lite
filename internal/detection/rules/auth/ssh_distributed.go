package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

type SSHDistributedBruteForceRule struct {
	Threshold int
	Window    time.Duration
}

func NewSSHDistributedBruteForceRule() *SSHDistributedBruteForceRule {
	return &SSHDistributedBruteForceRule{
		Threshold: 3, // number of IPs
		Window:    3 * time.Minute,
	}
}

func (r *SSHDistributedBruteForceRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource: "auth",
		Program:   "sshd",
		EventTypes: []string{
			"SSH_FAILED",
			"SSH_INVALID_USER",
		},
	}
}

func (r *SSHDistributedBruteForceRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {

	s := ctx.SSH
	ip := event.SourceIP
	user := event.Username
	now := event.Timestamp

	// need a user to track
	if user == "" {
		return nil
	}

	// initialize map if needed
	if s.IPsByUser[user] == nil {
		s.IPsByUser[user] = make(map[string]time.Time)
	}

	// record this IP attacking this user
	s.IPsByUser[user][ip] = now

	// prune old IPs (outside time window)
	for k, t := range s.IPsByUser[user] {
		if now.Sub(t) > r.Window {
			delete(s.IPsByUser[user], k)
		}
	}

	// check threshold (number of unique IPs)
	if len(s.IPsByUser[user]) >= r.Threshold {

		last := s.LastDistributedAlert[user]

		if now.Sub(last) > r.Window {

			alert := model.NewAlert(
				"Distributed Brute Force",
				model.SeverityHigh,
				"authentication",
				fmt.Sprintf("Multiple IPs targeting user %s", user),
				event,
				len(s.IPsByUser[user]),
			)

			s.LastDistributedAlert[user] = now

			return []*model.Alert{alert}
		}
	}

	return nil
}
