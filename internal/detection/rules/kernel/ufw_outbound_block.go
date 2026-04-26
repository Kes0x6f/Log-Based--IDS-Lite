package rule

import (
	"fmt"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/detection/context"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// suspiciousOutboundPorts maps destination port → description for outbound
// connections the firewall blocked. These are strong C2/exfil indicators
// because they represent *this machine* trying to reach out.
var suspiciousOutboundPorts = map[string]string{
	// Classic backdoor / Metasploit shells
	"4444":  "Metasploit default shell",
	"4445":  "common reverse shell",
	"1337":  "leet backdoor",
	"31337": "elite backdoor",

	// IRC (common C2 channel)
	"6667": "IRC plaintext C2",
	"6697": "IRC TLS C2",

	// Tor
	"9001": "Tor relay",
	"9030": "Tor directory",
	"9050": "Tor SOCKS proxy",
	"9051": "Tor control port",

	// Crypto-mining pools
	"3333":  "mining pool (Stratum)",
	"3334":  "mining pool (Stratum)",
	"14444": "mining pool",
	"45700": "mining pool",

	// Known exploit/exfil ports
	"1080": "SOCKS proxy (potential tunnel)",
}

// UFWOutboundBlockRule fires when the kernel's UFW blocks an outbound connection
// to a port associated with C2 frameworks, backdoors, or data exfiltration.
// An outbound block means the firewall is working, but the *attempt* itself
// is evidence of malicious code running on the host.
type UFWOutboundBlockRule struct {
	Cooldown time.Duration
}

func NewUFWOutboundBlockRule() *UFWOutboundBlockRule {
	return &UFWOutboundBlockRule{
		Cooldown: 15 * time.Minute,
	}
}

func (r *UFWOutboundBlockRule) Meta() detection.RuleMeta {
	return detection.RuleMeta{
		LogSource:  "ufw",
		Program:    "kernel",
		EventTypes: []string{"FW_BLOCK_OUT"},
	}
}

// ── Private state ──────────────────────────────────────────────────────────

// key is "srcIP:dstPort" — the local host IP + the suspicious remote port
type ufwOutboundState struct {
	lastAlertByKey map[string]time.Time
	lastAlertID    map[string]string
}

func newUFWOutboundState() *ufwOutboundState {
	return &ufwOutboundState{
		lastAlertByKey: make(map[string]time.Time),
		lastAlertID:    make(map[string]string),
	}
}

func getUFWOutboundState(ctx *context.DetectionContext) *ufwOutboundState {
	if v, ok := ctx.GetPrivate("ufw_outbound_block"); ok {
		return v.(*ufwOutboundState)
	}
	s := newUFWOutboundState()
	ctx.SetPrivate("ufw_outbound_block", s)
	return s
}

// ── Evaluate ───────────────────────────────────────────────────────────────

func (r *UFWOutboundBlockRule) Evaluate(event *model.NormalizedEvent, ctx *context.DetectionContext) []*model.Alert {
	s := getUFWOutboundState(ctx)
	src := event.SourceIP // local machine's IP for outbound
	port := event.Port    // destination port on the remote side
	now := event.Timestamp

	if port == "" {
		return nil
	}

	desc, ok := suspiciousOutboundPorts[port]
	if !ok {
		return nil
	}

	key := src + ":" + port
	last := s.lastAlertByKey[key]
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

	proto := event.Command
	if proto == "" {
		proto = "unknown"
	}

	alert := model.NewAlert(
		"UFW Suspicious Outbound Block",
		model.SeverityCritical,
		"c2",
		fmt.Sprintf(
			"Outbound connection to port %s/%s blocked — %s (possible C2 or exfil attempt)",
			port, proto, desc,
		),
		event,
		1,
	)

	s.lastAlertByKey[key] = now
	s.lastAlertID[key] = alert.ID

	return []*model.Alert{alert}
}
