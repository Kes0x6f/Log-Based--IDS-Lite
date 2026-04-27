package parsers

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// ── Compiled regexes ────────────────────────────────────────────────────────

// msg=audit(1609459200.123:456): — captures the unix seconds
var auditMsgRe = regexp.MustCompile(`msg=audit\((\d+)\.\d+:\d+\)`)

// key="exec_tmp"  or  key=exec_tmp
var auditKeyRe = regexp.MustCompile(`\bkey="?([^"\s]+)"?`)

// exe="/bin/bash"
var auditExeRe = regexp.MustCompile(`\bexe="([^"]+)"`)

// name="/etc/shadow"  or  name=/etc/shadow
var auditNameRe = regexp.MustCompile(`\bname="?([^"\s]+)"?`)

// comm="bash"
// Note: comm= is truncated to 15 characters by the kernel; use exe= when available.
var auditCommRe = regexp.MustCompile(`\bcomm="?([^"\s]+)"?`)

// auid=1000
var auditAuidRe = regexp.MustCompile(`\bauid=(\d+)`)

// uid=0
var auditUidRe = regexp.MustCompile(`\buid=(\d+)`)

// mode=0104755
var auditModeRe = regexp.MustCompile(`\bmode=(\d+)`)

// ── key → EventType table ───────────────────────────────────────────────────

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

// tmpDirPrefixes are the world-writable directories EXEC_TMP tracks.
// Keeping this in the parser avoids duplicating the list in the rule.
var tmpDirPrefixes = []string{"/tmp/", "/dev/shm/", "/run/shm/", "/var/tmp/"}

// ── Public entry points ────────────────────────────────────────────────────

// ParseRawAuditLine creates a NormalizedEvent from a raw audit.log line that
// has no syslog header prefix.  Called by ParserWorker when Source="audit"
// and the line starts with "type=".
//
//	Line: "type=SYSCALL msg=audit(1609459200.123:456): ... key=\"exec_tmp\""
func ParseRawAuditLine(line, source string) *model.NormalizedEvent {
	ts := auditTimestamp(line)

	event := &model.NormalizedEvent{
		Timestamp:  ts,
		LogSource:  source,
		Program:    "auditd",
		Message:    line,
		RawLine:    line,
		EventCount: 1,
	}

	return parseAuditRecord(line, event)
}

// ── Internal parser ────────────────────────────────────────────────────────

// parseAuditRecord classifies a single audit record line and populates the
// relevant NormalizedEvent fields.  Only records whose key= is in
// auditKeyToEventType produce an EventType; all others are left unset so the
// rule registry ignores them.
//
// Record type responsibilities:
//
//	PATH   → file-path events (FILE_READ, FILE_WRITE, CRON_WRITE, SERVICE_WRITE,
//	          TMP_WRITE, SETUID) and EXEC_TMP (script path, not interpreter).
//	SYSCALL → process-identity events (PTRACE, CAPSET).
//
// EXEC_TMP is intentionally sourced from PATH records, not SYSCALL records.
// The SYSCALL exe= field contains the interpreter (e.g. /bin/bash), which is
// useless for write→exec correlation.  The PATH record carries the actual
// script path (/tmp/malware.sh), which is what was written and must be matched
// against the TMP_WRITE map in AuditExecTmpRule.
func parseAuditRecord(line string, event *model.NormalizedEvent) *model.NormalizedEvent {
	recType := auditRecordType(line)
	key := auditField(auditKeyRe, line)
	eventType, known := auditKeyToEventType[key]
	if !known {
		return event // unrecognised key — rule registry will skip
	}

	// cap_prm=0000000000000000  (permitted capability set, hex)
	var auditCapPrmRe = regexp.MustCompile(`\bcap_prm=([0-9a-f]+)`)

	// cap_eff=0000000000000000  (effective capability set, hex)
	var auditCapEffRe = regexp.MustCompile(`\bcap_eff=([0-9a-f]+)`)

	// FIX: Resolve username unconditionally before the record-type switch.
	// Previously this was only called inside the SYSCALL branch, which meant
	// all PATH-based events (FILE_READ, FILE_WRITE, CRON_WRITE, SERVICE_WRITE,
	// TMP_WRITE, SETUID, EXEC_TMP) always had an empty Username in their alerts.
	// Both PATH and SYSCALL records carry auid= / uid= fields.
	event.Username = auditUser(line)

	switch recType {

	// ── PATH records carry the file name ───────────────────────────────────
	case "PATH":
		name := auditField(auditNameRe, line)
		if name == "" {
			return event
		}

		switch eventType {
		// File-path events are only emitted from PATH records.
		case "FILE_READ", "FILE_WRITE", "CRON_WRITE", "SERVICE_WRITE", "TMP_WRITE":
			event.EventType = eventType
			event.Command = name

		// SETUID: only alert when the new mode actually has the setuid bit.
		case "SETUID":
			if auditHasSetuid(line) {
				event.EventType = "SETUID"
				event.Command = name
			}

		// FIX: EXEC_TMP is sourced from PATH records, not SYSCALL records.
		//
		// When auditd processes execve, it emits multiple records sharing the
		// same serial number:
		//   type=SYSCALL ... exe="/bin/bash" key="exec_tmp"   ← interpreter
		//   type=PATH    ... name="/tmp/x.sh" item=1 key="exec_tmp" ← script ← we want this
		//
		// We only keep PATH records that point inside a temp dir (item=1 style),
		// filtering out item=0 records that carry the interpreter's own path.
		case "EXEC_TMP":
			for _, prefix := range tmpDirPrefixes {
				if strings.HasPrefix(name, prefix) {
					event.EventType = "EXEC_TMP"
					event.Command = name // script path — matches TMP_WRITE correlation key
					break
				}
			}
		}

	// ── SYSCALL records carry the calling binary ───────────────────────────
	case "SYSCALL":
		exe := auditField(auditExeRe, line)
		if exe == "" {
			// comm= is a 15-char kernel-truncated fallback; use only when exe= absent
			exe = auditField(auditCommRe, line)
		}

		switch eventType {
		// FIX: EXEC_TMP removed from this case.
		// The SYSCALL exe= value is the interpreter (/bin/bash, /bin/sh), not the
		// script path.  Emitting EXEC_TMP here would put the interpreter path into
		// event.Command, which would never match any TMP_WRITE entry keyed by the
		// script path.  The PATH record handler above emits the correct event.
		case "PTRACE", "CAPSET":
			event.EventType = eventType
			event.Command = exe
		}
	case "CAPSET":
		// Only process if the audit key is "capset"
		if eventType != "CAPSET" {
			return event
		}
		// Extract capability sets from the CAPSET record itself
		capPrm := auditField(auditCapPrmRe, line)
		capEff := auditField(auditCapEffRe, line)

		// Store them in Message so the rule can read them
		// Format: "cap_prm=<hex> cap_eff=<hex>"
		event.EventType = "CAPSET"
		event.Message = "cap_prm=" + capPrm + " cap_eff=" + capEff
	}

	return event
}

// ── Field extractors ────────────────────────────────────────────────────────

func auditRecordType(line string) string {
	// "type=SYSCALL ..." — type is always the first token
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

// auditHasSetuid returns true when the mode= field in a PATH record has the
// setuid bit (octal 04000) set.
func auditHasSetuid(line string) bool {
	modeStr := auditField(auditModeRe, line)
	if modeStr == "" {
		return false
	}
	// mode values in audit log are octal strings like "0104755"
	val, err := strconv.ParseInt(strings.TrimLeft(modeStr, "0"), 8, 64)
	if err != nil {
		return false
	}
	return (val & 04000) != 0
}

// auditUser resolves the real user from auid= (preferred) or uid=.
// Returns empty string when no usable uid is found.
func auditUser(line string) string {
	auid := auditField(auditAuidRe, line)
	// 4294967295 = (uint32)-1 = "unset"
	if auid != "" && auid != "4294967295" {
		return "uid:" + auid
	}
	uid := auditField(auditUidRe, line)
	if uid != "" {
		return "uid:" + uid
	}
	return ""
}

// auditTimestamp extracts unix seconds from msg=audit(SEC.MSEC:SERIAL)
// and returns a time.Time.  Falls back to time.Now() on parse failure.
func auditTimestamp(line string) time.Time {
	m := auditMsgRe.FindStringSubmatch(line)
	if len(m) == 2 {
		sec, err := strconv.ParseInt(m[1], 10, 64)
		if err == nil {
			return time.Unix(sec, 0)
		}
	}
	return time.Now()
}
