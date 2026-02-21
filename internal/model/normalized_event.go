package model

import (
	"time"
)

type NormalizedEvent struct {
	Timestamp     time.Time
	Host          string
	LogSource     string
	Program       string
	EventType     string
	Username      string
	SourceIP      string
	Port          string
	DestinationIP string
	Success       bool
	Message       string
	RawLine       string
}
