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

	// Context fields — populated directly from NormalizedEvent
	SourceIP  string
	Username  string
	Host      string
	Port      string // SSH source port / HTTP status code / UFW dest port
	Command   string // sudo command / HTTP method+URI / audit file path / binary
	LogSource string // auth | ufw | kern | audit | web
	RawLine   string // exact original log line that triggered the alert

	EventCount int

	FailCount      int
	IPCount        int
	AttackDuration int64
	TargetUser     string
	AuthMethod     string
	PortList       string
	CallerExe      string
	ThreatDetail   string

	IsUpdate        bool
	OriginalAlertID string
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
		ID:             GenerateID(),
		Timestamp:      event.Timestamp,
		RuleName:       ruleName,
		Severity:       severity,
		Category:       category,
		Message:        message,
		SourceIP:       event.SourceIP,
		Username:       event.Username,
		Host:           event.Host,
		Port:           event.Port,
		Command:        event.Command,
		LogSource:      event.LogSource,
		RawLine:        event.RawLine,
		EventCount:     count,
		FailCount:      event.FailCount,
		IPCount:        event.IPCount,
		AttackDuration: event.AttackDuration,
		TargetUser:     event.TargetUser,
		AuthMethod:     event.AuthMethod,
		PortList:       event.PortList,
		CallerExe:      event.CallerExe,
		ThreatDetail:   event.ThreatDetail,
	}
}

func GenerateID() string {
	return "ALT-" + uuid.New().String()
}
