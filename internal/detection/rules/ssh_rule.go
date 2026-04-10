package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

type SSHRule struct {
	BruteForceThreshold    int
	BruteForceWindow       time.Duration
	EnumerationThreshold   int
	EnumerationWindow      time.Duration
	SuccessAfterFailWindow time.Duration
	RapidReconnectWindow   time.Duration
	DistributedBruteWindow time.Duration
}

func NewSSHRule() *SSHRule {
	return &SSHRule{
		BruteForceThreshold:    5,
		BruteForceWindow:       2 * time.Minute,
		EnumerationThreshold:   5,
		EnumerationWindow:      3 * time.Minute,
		SuccessAfterFailWindow: 5 * time.Minute,
		RapidReconnectWindow:   2 * time.Minute,
		DistributedBruteWindow: 3 * time.Minute,
	}
}

func (r *SSHRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource: "auth",
		Program:   "sshd",
		EventTypes: []string{
			"SSH_FAILED",
			"SSH_SUCCESS",
			"SSH_INVALID_USER",
			"SSH_DISCONNECT",
		},
	}
}
func (r *SSHRule) Evaluate(event *model.NormalizedEvent, context *context.DetectionContext) []*model.Alert {

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
		for i := 0; i < event.EventCount; i++ {
			s.FailedByIP[ip] = append(s.FailedByIP[ip], now)
		}
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
		//Distributed Brute Force
		if s.IPsByUser[user] == nil {
			s.IPsByUser[user] = make(map[string]time.Time)
		}
		s.IPsByUser[user][ip] = now

		// prune old IPs
		for k, t := range s.IPsByUser[user] {
			if now.Sub(t) > 3*time.Minute {
				delete(s.IPsByUser[user], k)
			}
		}

		if len(s.IPsByUser[user]) >= 3 {
			last := s.LastDistributedAlert[user]
			if now.Sub(last) > 3*time.Minute {
				alerts = append(alerts, model.NewAlert(
					"Distributed Brute Force",
					model.SeverityHigh,
					"authentication",
					fmt.Sprintf("Multiple IPs targeting user %s", user),
					event,
					len(s.IPsByUser[user]),
				))
				s.LastDistributedAlert[user] = now
			}
		}

		if event.EventType == "SSH_INVALID_USER" {

			s.InvalidUserAttempts[ip] = append(s.InvalidUserAttempts[ip], now)
			s.InvalidUserAttempts[ip] = s.PruneOld(s.InvalidUserAttempts[ip], now, 2*time.Minute)

			if len(s.InvalidUserAttempts[ip]) >= 5 {
				last := s.LastInvalidUserAlert[ip]
				if now.Sub(last) > 2*time.Minute {
					alerts = append(alerts, model.NewAlert(
						"Invalid User Brute Force",
						model.SeverityMedium,
						"authentication",
						fmt.Sprintf("Multiple invalid user attempts from %s", ip),
						event,
						len(s.InvalidUserAttempts[ip]),
					))
					s.LastInvalidUserAlert[ip] = now
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

	//Rapid Reconnect
	case "SSH_DISCONNECT":
		ip := event.SourceIP

		if s.DisconnectsByIP[ip] == nil {
			s.DisconnectsByIP[ip] = []time.Time{}
		}

		for i := 0; i < event.EventCount; i++ {
			s.DisconnectsByIP[ip] = append(s.DisconnectsByIP[ip], now)
		}

		s.DisconnectsByIP[ip] = s.PruneOld(s.DisconnectsByIP[ip], now, r.RapidReconnectWindow)

		if len(s.DisconnectsByIP[ip]) >= 3 {
			last := s.LastReconnectAlert[ip]
			if now.Sub(last) > r.RapidReconnectWindow {
				alerts = append(alerts, model.NewAlert(
					"SSH Rapid Reconnect Attack",
					model.SeverityHigh,
					"authentication",
					fmt.Sprintf("Frequent reconnect attempts from %s", ip),
					event,
					len(s.DisconnectsByIP[ip]),
				))
				s.LastReconnectAlert[ip] = now
			}
		}
	}

	return alerts
}
