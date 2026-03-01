package model

import (
	"time"

	"github.com/google/uuid"
)

type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type Alert struct {
	ID        string
	Timestamp time.Time

	RuleName string
	Severity Severity
	Category string

	Message string

	SourceIP string
	Username string
	Host     string

	EventCount int
}

func NewAlert(
	ruleName string,
	severity Severity,
	category string,
	message string,
	event *NormalizedEvent,
	count int,
) *Alert {

	return &Alert{
		ID:         GenerateID(),
		Timestamp:  event.Timestamp,
		RuleName:   ruleName,
		Severity:   severity,
		Category:   category,
		Message:    message,
		SourceIP:   event.SourceIP,
		Username:   event.Username,
		Host:       event.Host,
		EventCount: count,
	}
}

func GenerateID() string {
	return "ALT-" + uuid.New().String()
}
