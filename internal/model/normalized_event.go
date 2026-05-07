package model

import (
	"time"
)

type NormalizedEvent struct {
	Timestamp      time.Time
	Host           string
	LogSource      string
	Program        string
	EventType      string
	Username       string
	SourceIP       string
	Port           string
	Command        string
	Message        string
	RawLine        string
	EventCount     int
	FailCount      int
	IPCount        int
	AttackDuration int64
	TargetUser     string
	AuthMethod     string
	PortList       string
	CallerExe      string
	ThreatDetail   string
}
