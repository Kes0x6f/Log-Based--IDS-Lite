package parsers

import (
	"regexp"
	"strings"

	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// ── Compiled regexes (unique prefixes to avoid collisions in the package) ──

// useradd[pid]: new user: name=bob, UID=1001, GID=1001, home=/home/bob, shell=/bin/bash
var acctNewUserRe = regexp.MustCompile(`new user: name=([^,]+)`)

// userdel[pid]: delete user 'bob'
var acctDeleteUserRe = regexp.MustCompile(`delete user '([^']+)'`)

// usermod[pid]: add 'bob' to group 'sudo'
// usermod[pid]: add 'bob' to shadow group 'sudo'
var acctAddToGroupRe = regexp.MustCompile(`add '([^']+)' to (?:shadow )?group '([^']+)'`)

// passwd[pid]: password changed for root
var acctPasswdChangedRe = regexp.MustCompile(`password changed for (\S+)`)

// ── Parser functions — one per program entry in programParsers ──

// UserAddParser handles "useradd" program lines.
func UserAddParser(event *model.NormalizedEvent) *model.NormalizedEvent {
	if m := acctNewUserRe.FindStringSubmatch(event.Message); len(m) == 2 {
		event.EventType = "ACCOUNT_CREATED"
		event.Username = strings.TrimSpace(m[1])
	}
	return event
}

// UserDelParser handles "userdel" program lines.
func UserDelParser(event *model.NormalizedEvent) *model.NormalizedEvent {
	if m := acctDeleteUserRe.FindStringSubmatch(event.Message); len(m) == 2 {
		event.EventType = "ACCOUNT_DELETED"
		event.Username = m[1]
	}
	return event
}

// UserModParser handles "usermod" program lines.
// Captures group-membership changes: "add 'bob' to group 'sudo'"
func UserModParser(event *model.NormalizedEvent) *model.NormalizedEvent {
	if m := acctAddToGroupRe.FindStringSubmatch(event.Message); len(m) == 3 {
		event.EventType = "GROUP_MODIFIED"
		event.Username = m[1] // user being added
		event.Command = m[2]  // group name — reusing Command field for group
	}
	return event
}

// PasswdParser handles "passwd" program lines.
func PasswdParser(event *model.NormalizedEvent) *model.NormalizedEvent {
	if m := acctPasswdChangedRe.FindStringSubmatch(event.Message); len(m) == 2 {
		event.EventType = "PASSWD_CHANGED"
		event.Username = m[1]
	}
	return event
}
