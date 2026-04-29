package parsers

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// ── Compiled regexes ────────────────────────────────────────────────────────

// msg=audit(1609459200.123:456) — group 1 = unix seconds, group 2 = serial
var auditMsgRe = regexp.MustCompile(`msg=audit\((\d+)\.\d+:(\d+)\)`)

var auditKeyRe = regexp.MustCompile(`\bkey="?([^"\s]+)"?`)
var auditExeRe = regexp.MustCompile(`\bexe="([^"]+)"`)
var auditNameRe = regexp.MustCompile(`\bname="?([^"\s]+)"?`)
var auditCommRe = regexp.MustCompile(`\bcomm="?([^"\s]+)"?`)
var auditAuidRe = regexp.MustCompile(`\bauid=(\d+)`)
var auditUidRe = regexp.MustCompile(`\buid=(\d+)`)
var auditModeRe = regexp.MustCompile(`\bmode=(\d+)`)
var auditCapPrmRe = regexp.MustCompile(`\bcap_prm=([0-9a-f]+)`)
var auditCapEffRe = regexp.MustCompile(`\bcap_eff=([0-9a-f]+)`)

// ── key → EventType ─────────────────────────────────────────────────────────

var auditKeyToEventType = map[string]string{
	"read_sensitive":  "FILE_READ",
	"write_sensitive": "FILE_WRITE",
	"cron_write":      "CRON_WRITE",
	"service_write":   "SERVICE_WRITE",
	"setuid_binary":   "SETUID",
	"ptrace":          "PTRACE",
	"capset":          "CAPSET",
	"exec_tmp":        "EXEC_TMP",
	"tmp_write":       "TMP_WRITE",
}

var tmpDirPrefixes = []string{"/tmp/", "/dev/shm/", "/run/shm/", "/var/tmp/"}

// ── Multi-record correlation ─────────────────────────────────────────────────
//
// Every audit event spans several lines sharing the same serial number:
//
//   type=SYSCALL msg=audit(T:99): exe="/usr/bin/cat" key="read_sensitive"
//   type=CWD     msg=audit(T:99): cwd="/root"
//   type=PATH    msg=audit(T:99): name="/etc/shadow"
//   type=EOE     msg=audit(T:99):
//
// SYSCALL has key= and exe=; PATH has name=. Neither alone is complete.
//
// CAPSET is different — cap values live on their own record type:
//
//   type=SYSCALL msg=audit(T:42): exe="/usr/bin/evil" key="capset"
//   type=CAPSET  msg=audit(T:42): cap_prm=00000000ffffffff cap_eff=...
//   type=EOE     msg=audit(T:42):
//
// Fix: buffer the SYSCALL partial; complete it when PATH or type=CAPSET arrives.

type partialAuditEvent struct {
	created   time.Time
	timestamp time.Time
	username  string
	eventType string
	exe       string
}

var (
	auditBufMu sync.Mutex
	auditBuf   = make(map[string]*partialAuditEvent)
)

const bufferTTL = 10 * time.Second

// ── Public entry point ─────────────────────────────────────────────────────

func ParseRawAuditLine(line, source string) *model.NormalizedEvent {
	recType := auditRecordType(line)
	serial := auditSerial(line)
	ts := auditTimestamp(line)

	pruneAuditBuffer()

	switch recType {

	// ── SYSCALL: identify intent; buffer for PATH or CAPSET record ───────────
	case "SYSCALL":
		key := auditField(auditKeyRe, line)
		eventType, known := auditKeyToEventType[key]
		if !known || serial == "" {
			return nil
		}

		exe := auditField(auditExeRe, line)
		if exe == "" {
			exe = auditField(auditCommRe, line)
		}

		// PTRACE: all data is on the SYSCALL record — emit immediately.
		if eventType == "PTRACE" {
			if exe == "" {
				exe = "unknown"
			}
			return &model.NormalizedEvent{
				Timestamp:  ts,
				LogSource:  source,
				Program:    "auditd",
				EventType:  "PTRACE",
				Username:   auditUser(line),
				Command:    exe,
				Message:    "exe=" + exe,
				RawLine:    line,
				EventCount: 1,
			}
		}

		// Everything else: buffer and wait for the completing record.
		auditBufMu.Lock()
		auditBuf[serial] = &partialAuditEvent{
			created:   time.Now(),
			timestamp: ts,
			username:  auditUser(line),
			eventType: eventType,
			exe:       exe,
		}
		auditBufMu.Unlock()
		return nil

	// ── type=CAPSET record: carries cap_prm/cap_eff for a capset syscall ────
	//
	// cap_prm and cap_eff are NOT on the SYSCALL record — only on this one.
	// Look up the buffered SYSCALL to get exe= and username=, then emit.
	case "CAPSET":
		if serial == "" {
			return nil
		}

		auditBufMu.Lock()
		partial, ok := auditBuf[serial]
		if ok {
			delete(auditBuf, serial)
		}
		auditBufMu.Unlock()

		if !ok || partial.eventType != "CAPSET" {
			return nil
		}

		exe := partial.exe
		if exe == "" {
			exe = "unknown"
		}

		capPrm := auditField(auditCapPrmRe, line)
		capEff := auditField(auditCapEffRe, line)

		// Message format matches parseCapFields() in audit_capset.go rule.
		return &model.NormalizedEvent{
			Timestamp:  partial.timestamp,
			LogSource:  source,
			Program:    "auditd",
			EventType:  "CAPSET",
			Username:   partial.username,
			Command:    exe,
			Message:    "cap_prm=" + capPrm + " cap_eff=" + capEff,
			RawLine:    line,
			EventCount: 1,
		}

	// ── PATH record: carries the file name for all file-path events ──────────
	case "PATH":
		if serial == "" {
			return nil
		}

		auditBufMu.Lock()
		partial, ok := auditBuf[serial]
		auditBufMu.Unlock()

		if !ok {
			return nil
		}

		name := auditField(auditNameRe, line)
		if name == "" {
			return nil
		}

		switch partial.eventType {

		case "FILE_READ", "FILE_WRITE", "CRON_WRITE", "SERVICE_WRITE", "TMP_WRITE":
			auditBufMu.Lock()
			delete(auditBuf, serial)
			auditBufMu.Unlock()

			// Pass exe via Message so rules can filter by calling binary.
			// Format: "exe=<path>"  — parsed with strings.TrimPrefix in rule.
			return &model.NormalizedEvent{
				Timestamp:  partial.timestamp,
				LogSource:  source,
				Program:    "auditd",
				EventType:  partial.eventType,
				Username:   partial.username,
				Command:    name,
				Message:    "exe=" + partial.exe,
				RawLine:    line,
				EventCount: 1,
			}

		case "SETUID":
			// Only fire if the PATH record shows the setuid bit is actually set.
			if !auditHasSetuid(line) {
				return nil
			}
			auditBufMu.Lock()
			delete(auditBuf, serial)
			auditBufMu.Unlock()

			return &model.NormalizedEvent{
				Timestamp:  partial.timestamp,
				LogSource:  source,
				Program:    "auditd",
				EventType:  "SETUID",
				Username:   partial.username,
				Command:    name,
				Message:    "exe=" + partial.exe,
				RawLine:    line,
				EventCount: 1,
			}

		case "EXEC_TMP":
			// auditd emits two PATH records for execve:
			//   item=0  the interpreter  (/bin/bash)  — skip
			//   item=1  the script path  (/tmp/x.sh)  — emit
			// Filter by whether name is inside a temp dir rather than parsing
			// item= so we work correctly across different auditd versions.
			for _, prefix := range tmpDirPrefixes {
				if strings.HasPrefix(name, prefix) {
					auditBufMu.Lock()
					delete(auditBuf, serial)
					auditBufMu.Unlock()

					return &model.NormalizedEvent{
						Timestamp:  partial.timestamp,
						LogSource:  source,
						Program:    "auditd",
						EventType:  "EXEC_TMP",
						Username:   partial.username,
						Command:    name,
						Message:    "exe=" + partial.exe,
						RawLine:    line,
						EventCount: 1,
					}
				}
			}
			// interpreter PATH record — leave buffer alive for the script record
			return nil
		}

	// ── EOE / PROCTITLE: flush the buffer entry for this serial ─────────────
	case "EOE", "PROCTITLE":
		if serial != "" {
			auditBufMu.Lock()
			delete(auditBuf, serial)
			auditBufMu.Unlock()
		}
	}

	return nil
}

// ── Field extractors ────────────────────────────────────────────────────────

func auditRecordType(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return strings.TrimPrefix(fields[0], "type=")
}

func auditField(re *regexp.Regexp, line string) string {
	m := re.FindStringSubmatch(line)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

// auditSerial extracts the serial from msg=audit(SEC.MSEC:SERIAL).
// This is the correlation key linking SYSCALL → CWD → PATH → CAPSET records.
func auditSerial(line string) string {
	m := auditMsgRe.FindStringSubmatch(line)
	if len(m) == 3 {
		return m[2]
	}
	return ""
}

// auditHasSetuid returns true when the mode= field on a PATH record
// has the setuid bit (octal 04000) set.
func auditHasSetuid(line string) bool {
	modeStr := auditField(auditModeRe, line)
	if modeStr == "" {
		return false
	}
	val, err := strconv.ParseInt(strings.TrimLeft(modeStr, "0"), 8, 64)
	if err != nil {
		return false
	}
	return (val & 04000) != 0
}

// auditUser resolves the acting user from auid= (login uid) or uid=.
// 4294967295 == (uint32)(-1) == unset.
func auditUser(line string) string {
	auid := auditField(auditAuidRe, line)
	if auid != "" && auid != "4294967295" {
		return "uid:" + auid
	}
	uid := auditField(auditUidRe, line)
	if uid != "" {
		return "uid:" + uid
	}
	return ""
}

// auditTimestamp extracts unix seconds from msg=audit(SEC.MSEC:SERIAL).
func auditTimestamp(line string) time.Time {
	m := auditMsgRe.FindStringSubmatch(line)
	if len(m) >= 2 {
		sec, err := strconv.ParseInt(m[1], 10, 64)
		if err == nil {
			return time.Unix(sec, 0)
		}
	}
	return time.Now()
}

// pruneAuditBuffer drops partial events older than bufferTTL.
func pruneAuditBuffer() {
	cutoff := time.Now().Add(-bufferTTL)
	auditBufMu.Lock()
	for serial, p := range auditBuf {
		if p.created.Before(cutoff) {
			delete(auditBuf, serial)
		}
	}
	auditBufMu.Unlock()
}
