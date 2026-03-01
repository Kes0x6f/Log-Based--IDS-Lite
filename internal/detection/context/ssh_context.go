package context

import "time"

type SSHState struct {
	FailedByIP               map[string][]time.Time
	FailedUsersByIP          map[string]map[string]time.Time
	RecentFailures           map[string][]time.Time
	LastBruteForceAlert      map[string]time.Time
	LastRootTargetAlert      map[string]time.Time
	LastEnumerationAlert     map[string]time.Time
	LastSuspiciousLoginAlert map[string]time.Time
}

func NewSSHState() *SSHState {
	return &SSHState{
		FailedByIP:               make(map[string][]time.Time),
		FailedUsersByIP:          make(map[string]map[string]time.Time),
		RecentFailures:           make(map[string][]time.Time),
		LastBruteForceAlert:      make(map[string]time.Time),
		LastEnumerationAlert:     make(map[string]time.Time),
		LastRootTargetAlert:      make(map[string]time.Time),
		LastSuspiciousLoginAlert: make(map[string]time.Time),
	}
}

func (s *SSHState) PruneOld(times []time.Time, now time.Time, window time.Duration) []time.Time {
	var pruned []time.Time
	for _, t := range times {
		if now.Sub(t) <= window {
			pruned = append(pruned, t)
		}
	}
	return pruned
}

func (s *SSHState) PruneUserEnumeration(ip string, now time.Time, window time.Duration) {

	users := s.FailedUsersByIP[ip]

	for user, t := range users {
		if now.Sub(t) > window {
			delete(users, user)
		}
	}
}
