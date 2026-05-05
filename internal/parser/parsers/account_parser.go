package parsers

import (
	"regexp"
	"strings"

	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

// ── Compiled regexes (unique prefixes to avoid collisions in the package) ──

// useradd[pid]: new user: name=bob, UID=1001, GID=1001, home=/home/bob, shell=/bin/bash
var acctNewUserRe = regexp.MustCompile(`new user: name=([^,]+)`)
var acctUIDRe = regexp.MustCompile(`UID=(\d+)`)
var acctGIDRe = regexp.MustCompile(`GID=(\d+)`)
var acctHomeRe = regexp.MustCompile(`home=([^,]+)`)
var acctShellRe = regexp.MustCompile(`shell=(\S+)`)

// userdel[pid]: delete user 'bob'
var acctDeleteUserRe = regexp.MustCompile(`delete user '([^']+)'`)

// usermod[pid]: add 'bob' to group 'sudo'
// usermod[pid]: add 'bob' to shadow group 'sudo'
var acctAddToGroupRe = regexp.MustCompile(`add '([^']+)' to (?:shadow )?group '([^']+)'`)

// passwd[pid]: password changed for root
var acctPasswdChangedRe = regexp.MustCompile(`password changed for (\S+)`)

// ── Parser functions — one per program entry in programParsers ──

// UserAddParser handles "useradd" program lines.
// Sets Command to "UID=<n> GID=<n> home=<path> shell=<path>" so the alert
// detail page can immediately show what kind of account was created without
// requiring a separate log lookup.
func UserAddParser(event *model.NormalizedEvent) *model.NormalizedEvent {
	if m := acctNewUserRe.FindStringSubmatch(event.Message); len(m) == 2 {
		event.EventType = "ACCOUNT_CREATED"
		event.Username = strings.TrimSpace(m[1])

		// Build a structured summary of the new account's attributes.
		var parts []string
		if uid := acctUIDRe.FindStringSubmatch(event.Message); len(uid) == 2 {
			parts = append(parts, "UID="+uid[1])
		}
		if gid := acctGIDRe.FindStringSubmatch(event.Message); len(gid) == 2 {
			parts = append(parts, "GID="+gid[1])
		}
		if home := acctHomeRe.FindStringSubmatch(event.Message); len(home) == 2 {
			parts = append(parts, "home="+strings.TrimSpace(home[1]))
		}
		if shell := acctShellRe.FindStringSubmatch(event.Message); len(shell) == 2 {
			parts = append(parts, "shell="+shell[1])
		}
		if len(parts) > 0 {
			event.Command = strings.Join(parts, " ")
		}
	}
	return event
}

// UserDelParser handles "userdel" program lines.
func UserDelParser(event *model.NormalizedEvent) *model.NormalizedEvent {
	if m := acctDeleteUserRe.FindStringSubmatch(event.Message); len(m) == 2 {
		event.EventType = "ACCOUNT_DELETED"
		event.Username = m[1]
		event.Command = "deleted:" + m[1]
	}
	return event
}

// UserModParser handles "usermod" program lines.
// Captures group-membership changes: "add 'bob' to group 'sudo'"
func UserModParser(event *model.NormalizedEvent) *model.NormalizedEvent {
	if m := acctAddToGroupRe.FindStringSubmatch(event.Message); len(m) == 3 {
		event.EventType = "GROUP_MODIFIED"
		event.Username = m[1]           // user being added
		event.Command = "group:" + m[2] // group name, prefixed for clarity
	}
	return event
}

// PasswdParser handles "passwd" program lines.
// Sets Command to "account:<name>" so the changed account is visible
// even if it differs from the acting user.
func PasswdParser(event *model.NormalizedEvent) *model.NormalizedEvent {
	if m := acctPasswdChangedRe.FindStringSubmatch(event.Message); len(m) == 2 {
		event.EventType = "PASSWD_CHANGED"
		event.Username = m[1]
		event.Command = "account:" + m[1]
	}
	return event
}
