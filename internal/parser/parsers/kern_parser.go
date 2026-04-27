package parsers

import (
	"regexp"
	"strings"

	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// ── Compiled regexes ────────────────────────────────────────────────────────

// kernel timestamp prefix: [12345.678901]
var kernTimestampRe = regexp.MustCompile(`^\[\s*[\d.]+\]\s*`)

// segfault: "sshd[1234]: segfault at 7f00... ip ..."
var kernSegfaultRe = regexp.MustCompile(`^(\S+?)\[\d+\]:\s+segfault\s+at`)

// OOM kill (two variants):
//
//	"Out of memory: Kill process 1234 (apache2) score 900 ..."
//	"Killed process 1234 (bash) total-vm:..."
var kernOOMKillRe = regexp.MustCompile(`(?:Out of memory: Kill|Killed)\s+process\s+\d+\s+\(([^)]+)\)`)

// disk/block I/O error — device name extraction
// "blk_update_request: I/O error, dev sda, sector ..."
// "Buffer I/O error on dev sda1, logical block ..."
var kernDevRe = regexp.MustCompile(`\bdev(?:ice)?\s+([a-z]+\d*[a-z]?\d*)\b`)

// ── KernParser ─────────────────────────────────────────────────────────────

// KernParser is registered as the "kernel" program parser in programParsers.
// It handles two families of kernel log lines in a single pass:
//
//  1. UFW lines (contain "[UFW ") → delegated to UFWParser.
//  2. kern.log / syslog kernel lines → classified into KMOD_LOAD, SEGFAULT,
//     OOM_KILL, or DISK_ERROR.
//
// Keeping both families in one function avoids a programParsers key conflict,
// since both ufw.log and kern.log emit lines with Program="kernel".
// Rule isolation is enforced downstream by the RuleRegistry (LogSource key).
func KernParser(event *model.NormalizedEvent) *model.NormalizedEvent {
	msg := event.Message

	// ── 1. UFW lines ────────────────────────────────────────────────────────
	// UFW writes to both ufw.log and kern.log. The ufw.log FileCollector
	// (LogSource="ufw") is the authoritative source for UFW events.
	// Lines arriving here carry LogSource="kern" and must be silently dropped
	// so the rule registry never sees them — otherwise every UFW event fires
	// twice and port-scan / repeated-block counters are artificially doubled.
	if strings.Contains(msg, "[UFW ") {
		if event.LogSource == "kern" {
			return event // kern.log duplicate — drop it
		}
	}

	// ── 2. Strip the optional kernel timestamp "[12345.678] " prefix ────────
	clean := kernTimestampRe.ReplaceAllString(msg, "")

	// ── 3. Kernel module load ───────────────────────────────────────────────
	// Target patterns:
	//   "evilmod: loading out-of-tree module taints kernel."
	//   "evil.ko: module verification failed: signature and/or required key missing - tainting kernel"
	switch {
	case strings.Contains(clean, "loading out-of-tree module") ||
		strings.Contains(clean, "module verification failed") ||
		strings.Contains(clean, "tainting kernel"):

		event.EventType = "KMOD_LOAD"
		// Module name is the word before the first ':'
		if idx := strings.Index(clean, ":"); idx > 0 {
			event.Command = strings.TrimSpace(clean[:idx])
		}

	// ── 4. Segfault ──────────────────────────────────────────────────────────
	// "sshd[1234]: segfault at 7f..."
	case strings.Contains(clean, "segfault"):
		event.EventType = "SEGFAULT"
		if m := kernSegfaultRe.FindStringSubmatch(clean); len(m) == 2 {
			event.Command = m[1] // binary name (sshd, sudo, …)
		}

	// ── 5. OOM kill ──────────────────────────────────────────────────────────
	case strings.Contains(clean, "Out of memory") || strings.Contains(clean, "Killed process"):
		event.EventType = "OOM_KILL"
		if m := kernOOMKillRe.FindStringSubmatch(clean); len(m) == 2 {
			event.Command = m[1] // process name
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
	}

	return event
}
