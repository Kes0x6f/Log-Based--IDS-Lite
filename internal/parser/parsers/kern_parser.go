package parsers

import (
	"regexp"
	"strings"

	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// ── Compiled regexes ────────────────────────────────────────────────────────

// kernel timestamp prefix: [12345.678901]
var kernTimestampRe = regexp.MustCompile(`^\[\s*[\d.]+\]\s*`)

// segfault: "sshd[1234]: segfault at 7f004b2c2000 ip ..."
var kernSegfaultRe = regexp.MustCompile(`^(\S+?)\[\d+\]:\s+segfault\s+at`)
var kernFaultAddrRe = regexp.MustCompile(`segfault at ([0-9a-f]+)`)

// OOM kill:
//
//	"Out of memory: Kill process 1234 (apache2) score 900 ..."
//	"Killed process 1234 (bash) total-vm:..."
var kernOOMKillRe = regexp.MustCompile(`(?:Out of memory: Kill|Killed)\s+process\s+\d+\s+\(([^)]+)\)`)
var kernOOMScoreRe = regexp.MustCompile(`score\s+(\d+)`)

// disk/block I/O error — device name extraction
var kernDevRe = regexp.MustCompile(`\bdev(?:ice)?\s+([a-z]+\d*[a-z]?\d*)\b`)

// ── KernParser ─────────────────────────────────────────────────────────────

// KernParser is registered as the "kernel" program parser in programParsers.
// It handles two families of kernel log lines in a single pass:
//
//  1. UFW lines (contain "[UFW ") → delegated to UFWParser.
//  2. kern.log / syslog kernel lines → classified into KMOD_LOAD, SEGFAULT,
//     OOM_KILL, or DISK_ERROR.
func KernParser(event *model.NormalizedEvent) *model.NormalizedEvent {
	msg := event.Message

	// ── 1. UFW lines ────────────────────────────────────────────────────────
	// UFW writes to both ufw.log and kern.log.  Lines from kern.log carry
	// LogSource="kern" and must be silently dropped to prevent double-counting.
	if strings.Contains(msg, "[UFW ") {
		if event.LogSource == "kern" {
			return event
		}
	}

	// ── 2. Strip optional kernel timestamp "[12345.678] " prefix ────────────
	clean := kernTimestampRe.ReplaceAllString(msg, "")

	switch {

	// ── 3. Kernel module load ───────────────────────────────────────────────
	// "evilmod: loading out-of-tree module taints kernel."
	// "evil.ko: module verification failed: signature and/or required key missing - tainting kernel"
	case strings.Contains(clean, "loading out-of-tree module") ||
		strings.Contains(clean, "module verification failed") ||
		strings.Contains(clean, "tainting kernel"):

		event.EventType = "KMOD_LOAD"

		// Module name is the word before the first ':'
		if idx := strings.Index(clean, ":"); idx > 0 {
			event.Command = strings.TrimSpace(clean[:idx])
		}

		// ThreatDetail: distinguish out-of-tree from signature-verification failure.
		// These have different security implications:
		//   out-of-tree  — not part of the running kernel, unusual but can be DKMS
		//   unsigned     — no valid signature, stronger rootkit indicator
		switch {
		case strings.Contains(clean, "loading out-of-tree module"):
			event.ThreatDetail = "type:out-of-tree"
		case strings.Contains(clean, "module verification failed"):
			event.ThreatDetail = "type:unsigned"
		default:
			event.ThreatDetail = "type:taint"
		}

	// ── 4. Segfault ──────────────────────────────────────────────────────────
	// "sshd[1234]: segfault at 7f004b2c2000 ip 00007f004b2c2000 ..."
	case strings.Contains(clean, "segfault"):
		event.EventType = "SEGFAULT"

		if m := kernSegfaultRe.FindStringSubmatch(clean); len(m) == 2 {
			event.Command = m[1] // binary name (sshd, sudo, …)
		}

		// ThreatDetail: fault address gives analysts a starting point for
		// determining whether this is a null-deref, heap corruption, or ROP.
		if m := kernFaultAddrRe.FindStringSubmatch(clean); len(m) == 2 {
			event.ThreatDetail = "addr:" + m[1]
		}

	// ── 5. OOM kill ──────────────────────────────────────────────────────────
	case strings.Contains(clean, "Out of memory") || strings.Contains(clean, "Killed process"):
		event.EventType = "OOM_KILL"

		if m := kernOOMKillRe.FindStringSubmatch(clean); len(m) == 2 {
			event.Command = m[1] // process name
		}

		// ThreatDetail: OOM score. The kernel assigns 0–1000 to each process
		// based on memory usage and other factors. A score of 1000 means the
		// process was the top candidate; a score near 0 indicates the kernel
		// killed something it normally would not touch — more suspicious.
		if m := kernOOMScoreRe.FindStringSubmatch(clean); len(m) == 2 {
			event.ThreatDetail = "score:" + m[1]
		}

	// ── 6. Disk / block I/O error ────────────────────────────────────────────
	case strings.Contains(clean, "I/O error") ||
		strings.Contains(clean, "blk_update_request") ||
		strings.Contains(clean, "Buffer I/O") ||
		strings.Contains(clean, "EXT4-fs error") ||
		strings.Contains(clean, "EXT3-fs error") ||
		strings.Contains(clean, "XFS ("):

		event.EventType = "DISK_ERROR"

		if m := kernDevRe.FindStringSubmatch(clean); len(m) == 2 {
			event.Command = m[1] // device name: sda, nvme0n1, …
		}

		// ThreatDetail: I/O direction when determinable from the message.
		// "READA" / "READ" suffix in blk_update_request indicates a read error.
		// Write errors often appear as "WRITE" in the operation field.
		switch {
		case strings.Contains(clean, " READ") || strings.Contains(clean, "READA"):
			event.ThreatDetail = "op:read"
		case strings.Contains(clean, " WRITE"):
			event.ThreatDetail = "op:write"
		}
	}

	return event
}
