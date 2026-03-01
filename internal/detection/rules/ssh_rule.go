package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

type SSHRule struct {
	BruteForceThreshold    int
	BruteForceWindow       time.Duration
	EnumerationThreshold   int
	EnumerationWindow      time.Duration
	SuccessAfterFailWindow time.Duration
}

func NewSSHRule() *SSHRule {
	return &SSHRule{
		BruteForceThreshold:    5,
		BruteForceWindow:       2 * time.Minute,
		EnumerationThreshold:   5,
		EnumerationWindow:      3 * time.Minute,
		SuccessAfterFailWindow: 5 * time.Minute,
	}
}

func (r *SSHRule) Evaluate(event *model.NormalizedEvent, context *context.DetectionContext) []*model.Alert {

	if event.Program != "sshd" {
		return nil
	}

	var alerts []*model.Alert
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
			last := s.LastBruteForceAlert[ip]
			if now.Sub(last) > r.BruteForceWindow {
				alert := model.NewAlert(
					"SSH Brute Force",
					model.SeverityHigh,
					"authentication",
					fmt.Sprintf("Multiple failed SSH login attempts from %s", ip),
					event,
					len(s.FailedByIP[ip]),
				)
				alerts = append(alerts, alert)
				s.LastBruteForceAlert[ip] = now
			}
		}
		// Track enumeration
		if user != "" {

			if s.FailedUsersByIP[ip] == nil {
				s.FailedUsersByIP[ip] = make(map[string]time.Time)
			}

			s.FailedUsersByIP[ip][user] = now
			s.PruneUserEnumeration(ip, now, r.EnumerationWindow)

			if len(s.FailedUsersByIP[ip]) >= r.EnumerationThreshold {
				last := s.LastEnumerationAlert[ip]
				if now.Sub(last) > r.EnumerationWindow {
					alert := model.NewAlert(
						"SSH Username Enumeration",
						model.SeverityHigh,
						"authentication",
						fmt.Sprintf("Multiple username enumeration attempts from %s", ip),
						event,
						len(s.FailedUsersByIP[ip]),
					)
					alerts = append(alerts, alert)
					s.LastEnumerationAlert[ip] = now
				}
			}

			// Track for success-after-failure
			s.RecentFailures[ip] = append(s.RecentFailures[ip], now)
			s.RecentFailures[ip] = s.PruneOld(s.RecentFailures[ip], now, r.SuccessAfterFailWindow)

			s.RootFailures[ip] = append(s.RootFailures[ip], now)
			s.RootFailures[ip] = s.PruneOld(s.RootFailures[ip], now, r.BruteForceWindow)
			// Root targeting
			if user == "root" {
				last := s.LastRootTargetAlert[ip]
				if now.Sub(last) > r.BruteForceWindow {
					alert := model.NewAlert(
						"SSH Root Targeting",
						model.SeverityHigh,
						"authentication",
						fmt.Sprintf("SSH Root Targeting attempt from %s", ip),
						event,
						len(s.RootFailures[ip]),
					)
					alerts = append(alerts, alert)
					s.LastRootTargetAlert[ip] = now
				}
			}
		}

	// ---------------------------------
	// SSH SUCCESS
	// ---------------------------------
	case "SSH_SUCCESS":

		ip := event.SourceIP

		if failures, exists := s.RecentFailures[ip]; exists {
			if len(failures) >= 3 {
				last := s.LastSuspiciousLoginAlert[ip]
				if now.Sub(last) > r.SuccessAfterFailWindow {
					alert := model.NewAlert(
						"SSH Suspicious Login",
						model.SeverityCritical,
						"authentication",
						fmt.Sprintf(
							"SSH login succeeded after %d failed attempts from %s",
							len(failures),
							ip,
						),
						event,
						len(failures),
					)
					alerts = append(alerts, alert)
					s.LastSuspiciousLoginAlert[ip] = now
				}
			}
		}

		// Reset after success
		delete(s.RecentFailures, ip)
		delete(s.FailedByIP, ip)
		delete(s.FailedUsersByIP, ip)
	}

	return alerts
}
