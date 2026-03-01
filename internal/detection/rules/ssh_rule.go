package rule

import (
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

type SSHRule struct {
	RuleName string
	Severity string

	BruteForceThreshold    int
	BruteForceWindow       time.Duration
	EnumerationThreshold   int
	EnumerationWindow      time.Duration
	SuccessAfterFailWindow time.Duration
}

func NewSSHRule() *SSHRule {
	return &SSHRule{
		RuleName: "SSH ",
		Severity: "HIGH",

		BruteForceThreshold:    5,
		BruteForceWindow:       2 * time.Minute,
		EnumerationThreshold:   5,
		EnumerationWindow:      3 * time.Minute,
		SuccessAfterFailWindow: 5 * time.Minute,
	}
}

func (r *SSHRule) Evaluate(event *model.NormalizedEvent, context *context.DetectionContext) []string {

	var alerts []string
	s := context.SSH
	now := event.Timestamp

	switch event.EventType {

	// ---------------------------------
	// SSH FAILED EVENTS
	// ---------------------------------
	case "SSH_FAILED", "SSH_INVALID_USER":

		ip := event.SourceIP
		user := event.Username

		// Track failures by IP
		s.FailedByIP[ip] = append(s.FailedByIP[ip], now)
		s.FailedByIP[ip] = s.PruneOld(s.FailedByIP[ip], now, r.BruteForceWindow)

		if len(s.FailedByIP[ip]) >= r.BruteForceThreshold {
			alerts = append(alerts, "SSH Brute Force detected from "+ip)
		}

		// Track enumeration
		if s.FailedUsersByIP[ip] == nil {
			s.FailedUsersByIP[ip] = make(map[string]time.Time)
		}

		s.FailedUsersByIP[ip][user] = now
		s.PruneUserEnumeration(ip, now, r.EnumerationWindow)

		if len(s.FailedUsersByIP[ip]) >= r.EnumerationThreshold {
			alerts = append(alerts, "SSH Username Enumeration from "+ip)
		}

		// Track for success-after-failure
		s.RecentFailures[ip] = append(s.RecentFailures[ip], now)
		s.RecentFailures[ip] = s.PruneOld(s.RecentFailures[ip], now, r.SuccessAfterFailWindow)

		// Root targeting
		if user == "root" {
			alerts = append(alerts, "SSH Root Targeting attempt from "+ip)
		}

	// ---------------------------------
	// SSH SUCCESS
	// ---------------------------------
	case "SSH_SUCCESS":

		ip := event.SourceIP

		if failures, exists := s.RecentFailures[ip]; exists {
			if len(failures) >= 3 {
				alerts = append(alerts, "Possible compromise: SSH success after failures from "+ip)
			}
		}

		// Reset after success
		delete(s.RecentFailures, ip)
		delete(s.FailedByIP, ip)
		delete(s.FailedUsersByIP, ip)
	}

	return alerts
}

//just initial detection for ssh logs
