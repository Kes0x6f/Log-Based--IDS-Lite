package context

import "time"

type SudoState struct {
	FailedByUser        map[string][]time.Time
	RecentFails         map[string][]time.Time
	CommandsByUser      map[string][]time.Time
	RootSessionsByUser  map[string][]time.Time
	SessionStartsByUser map[string][]time.Time

	LastExecByUser      map[string][]time.Time
	LastAbuseAlert      map[string]time.Time
	LastBruteForceAlert map[string]time.Time
	LastSuccessAlert    map[string]time.Time
	LastRootAlert       map[string]time.Time
	LastSessionAlert    map[string]time.Time
}

func NewSudoState() *SudoState {
	return &SudoState{
		FailedByUser:        make(map[string][]time.Time),
		RecentFails:         make(map[string][]time.Time),
		CommandsByUser:      make(map[string][]time.Time),
		RootSessionsByUser:  make(map[string][]time.Time),
		SessionStartsByUser: make(map[string][]time.Time),

		LastBruteForceAlert: make(map[string]time.Time),
		LastSuccessAlert:    make(map[string]time.Time),
		LastExecByUser:      make(map[string][]time.Time),
		LastAbuseAlert:      make(map[string]time.Time),
		LastRootAlert:       make(map[string]time.Time),
		LastSessionAlert:    make(map[string]time.Time),
	}
}
