package context

import "time"

type SSHState struct {
	InvalidUserAttempts map[string][]time.Time
	FailedByIP          map[string][]time.Time
	FailedUsersByIP     map[string]map[string]time.Time
	RecentFailures      map[string][]time.Time
	RootFailures        map[string][]time.Time
	DisconnectsByIP     map[string][]time.Time
	IPsByUser           map[string]map[string]time.Time

	LastInvalidUserAlert     map[string]time.Time
	LastDistributedAlert     map[string]time.Time
	LastReconnectAlert       map[string]time.Time
	LastBruteForceAlert      map[string]time.Time
	LastRootTargetAlert      map[string]time.Time
	LastEnumerationAlert     map[string]time.Time
	LastSuspiciousLoginAlert map[string]time.Time
}

func NewSSHState() *SSHState {
	return &SSHState{
		InvalidUserAttempts:      make(map[string][]time.Time),
		FailedByIP:               make(map[string][]time.Time),
		FailedUsersByIP:          make(map[string]map[string]time.Time),
		RecentFailures:           make(map[string][]time.Time),
		RootFailures:             make(map[string][]time.Time),
		DisconnectsByIP:          make(map[string][]time.Time),
		IPsByUser:                make(map[string]map[string]time.Time),
		LastInvalidUserAlert:     make(map[string]time.Time),
		LastDistributedAlert:     make(map[string]time.Time),
		LastReconnectAlert:       make(map[string]time.Time),
		LastBruteForceAlert:      make(map[string]time.Time),
		LastEnumerationAlert:     make(map[string]time.Time),
		LastRootTargetAlert:      make(map[string]time.Time),
		LastSuspiciousLoginAlert: make(map[string]time.Time),
	}
}

func (s *SSHState) PruneUserEnumeration(ip string, now time.Time, window time.Duration) {

	users := s.FailedUsersByIP[ip]

	for user, t := range users {
		if now.Sub(t) > window {
			delete(users, user)
		}
	}
}
