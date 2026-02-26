package sshdetection

import (
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

const (
	BruteForceThreshold    = 5
	BruteForceWindow       = 2 * time.Minute
	EnumerationThreshold   = 5
	EnumerationWindow      = 3 * time.Minute
	SuccessAfterFailWindow = 5 * time.Minute
)

type SSHDetectionState struct {
	FailedByIP      map[string][]time.Time
	FailedUsersByIP map[string]map[string]time.Time
	RecentFailures  map[string][]time.Time
}

func NewSSHDetectionState() *SSHDetectionState {
	return &SSHDetectionState{
		FailedByIP:      make(map[string][]time.Time),
		FailedUsersByIP: make(map[string]map[string]time.Time),
		RecentFailures:  make(map[string][]time.Time),
	}
}

func (s *SSHDetectionState) Process(event *model.NormalizedEvent) []string {

	var alerts []string
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
		s.FailedByIP[ip] = pruneOld(s.FailedByIP[ip], now, BruteForceWindow)

		if len(s.FailedByIP[ip]) >= BruteForceThreshold {
			alerts = append(alerts, "SSH Brute Force detected from "+ip)
		}

		// Track enumeration
		if s.FailedUsersByIP[ip] == nil {
			s.FailedUsersByIP[ip] = make(map[string]time.Time)
		}

		s.FailedUsersByIP[ip][user] = now
		s.pruneUserEnumeration(ip, now)

		if len(s.FailedUsersByIP[ip]) >= EnumerationThreshold {
			alerts = append(alerts, "SSH Username Enumeration from "+ip)
		}

		// Track for success-after-failure
		s.RecentFailures[ip] = append(s.RecentFailures[ip], now)
		s.RecentFailures[ip] = pruneOld(s.RecentFailures[ip], now, SuccessAfterFailWindow)

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

func pruneOld(times []time.Time, now time.Time, window time.Duration) []time.Time {
	var pruned []time.Time
	for _, t := range times {
		if now.Sub(t) <= window {
			pruned = append(pruned, t)
		}
	}
	return pruned
}

func (s *SSHDetectionState) pruneUserEnumeration(ip string, now time.Time) {

	users := s.FailedUsersByIP[ip]

	for user, t := range users {
		if now.Sub(t) > EnumerationWindow {
			delete(users, user)
		}
	}
}
