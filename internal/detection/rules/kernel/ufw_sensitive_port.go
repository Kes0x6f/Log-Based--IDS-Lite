package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// sensitivePortMeta maps destination port numbers to a human-readable service
// name and the severity level the alert should carry.
type sensitivePortMeta struct {
	Service  string
	Severity model.Severity
}

// sensitiveInboundPorts covers services where an external probe warrants
// immediate review regardless of whether the host actually listens on that port.
var sensitiveInboundPorts = map[string]sensitivePortMeta{
	// Remote access — direct exploitation targets
	"22":   {"SSH", model.SeverityHigh},
	"23":   {"Telnet", model.SeverityCritical},
	"3389": {"RDP", model.SeverityHigh},
	"5900": {"VNC", model.SeverityHigh},

	// Databases — data exfiltration risk
	"3306":  {"MySQL", model.SeverityHigh},
	"5432":  {"PostgreSQL", model.SeverityHigh},
	"6379":  {"Redis", model.SeverityCritical}, // Redis is unauthenticated by default
	"27017": {"MongoDB", model.SeverityCritical},
	"9200":  {"Elasticsearch", model.SeverityCritical},
	"5984":  {"CouchDB", model.SeverityHigh},

	// Container / orchestration
	"2375": {"Docker (unencrypted)", model.SeverityCritical},
	"2376": {"Docker TLS", model.SeverityHigh},
	"6443": {"Kubernetes API", model.SeverityCritical},
	"2379": {"etcd", model.SeverityCritical},

	// Network services
	"161": {"SNMP", model.SeverityHigh},
	"389": {"LDAP", model.SeverityHigh},
	"636": {"LDAPS", model.SeverityHigh},
}

// UFWSensitivePortRule fires on the *first* inbound block from each IP targeting
// a sensitive port. A per-IP+port cooldown prevents alert floods from scanners
// that probe the same port repeatedly.
type UFWSensitivePortRule struct {
	Cooldown time.Duration
}

func NewUFWSensitivePortRule() *UFWSensitivePortRule {
	return &UFWSensitivePortRule{
		Cooldown: 10 * time.Minute,
	}
}

func (r *UFWSensitivePortRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:  "ufw",
		Program:    "kernel",
		EventTypes: []string{"FW_BLOCK"},
	}
}

// ── Private state ──────────────────────────────────────────────────────────

// key is "ip:port"
type ufwSensitivePortState struct {
	lastAlertByIPPort map[string]time.Time
	lastAlertID       map[string]string
}

func newUFWSensitivePortState() *ufwSensitivePortState {
	return &ufwSensitivePortState{
		lastAlertByIPPort: make(map[string]time.Time),
		lastAlertID:       make(map[string]string),
	}
}

func getUFWSensitivePortState(ctx *context.DetectionContext) *ufwSensitivePortState {
	if v, ok := ctx.GetPrivate("ufw_sensitive_port"); ok {
		return v.(*ufwSensitivePortState)
	}
	s := newUFWSensitivePortState()
	ctx.SetPrivate("ufw_sensitive_port", s)
	return s
}

// ── Evaluate ───────────────────────────────────────────────────────────────

func (r *UFWSensitivePortRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {
	s := getUFWSensitivePortState(ctx)
	ip := event.SourceIP
	port := event.Port
	now := event.Timestamp

	if ip == "" || port == "" {
		return nil
	}

	meta, ok := sensitiveInboundPorts[port]
	if !ok {
		return nil
	}

	key := ip + ":" + port
	last := s.lastAlertByIPPort[key]
	inCooldown := !last.IsZero() && now.Sub(last) <= r.Cooldown

	if inCooldown {
		if id := s.lastAlertID[key]; id != "" {
			return []*model.Alert{{
				IsUpdate:        true,
				OriginalAlertID: id,
				EventCount:      1,
			}}
		}
		return nil
	}

	proto := event.Command // PROTO= field stored here by UFWParser
	if proto == "" {
		proto = "unknown"
	}

	event.ThreatDetail = fmt.Sprintf("service:%s", meta.Service)

	alert := model.NewAlert(
		"UFW Sensitive Port Probe",
		meta.Severity,
		"reconnaissance",
		fmt.Sprintf("IP %s probed %s (port %s/%s)", ip, meta.Service, port, proto),
		event,
		1,
	)

	s.lastAlertByIPPort[key] = now
	s.lastAlertID[key] = alert.ID

	return []*model.Alert{alert}
}
