//go:build linux

package collector

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os/exec"
	"time"

	nflog "github.com/florianl/go-nflog/v2"

	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
	"github.com/Kes0x6f/Log-Based--IDS/internal/stream"
)

const nflogGroup = 100

// NFLOGCollector subscribes to the kernel's netfilter NFLOG facility and
// produces NormalizedEvents directly — no log file, no rate limiting.
//
// Start() opens the netlink socket first, then inserts iptables rules into
// ufw-logging-deny so that every denied packet is captured before UFW's
// rate-limited LOG target.  On context cancellation the rules are removed
// and the socket is closed cleanly.
type NFLOGCollector struct {
	Broadcaster *stream.Broadcaster
	Stats       *SourceStats
}

// ── iptables rule spec ─────────────────────────────────────────────────────

// suspiciousOutboundPorts is the comma-separated list of ports monitored for
// outbound C2 / exfiltration activity.  Must stay in sync with
// suspiciousOutboundPorts in ufw_outbound_block.go.
// iptables multiport supports a maximum of 15 ports; this list has exactly 15.
const suspiciousOutboundPorts = "1080,1337,3333,3334,4444,4445,6667,6697,9001,9030,9050,9051,14444,31337,45700"

// inboundNFLOGArgs returns rule args for the inbound logging chains.
// No port filter — we want to see all inbound denied packets.
func inboundNFLOGArgs() []string {
	return []string{
		"-j", "NFLOG",
		"--nflog-group", fmt.Sprintf("%d", nflogGroup),
		"--nflog-prefix", "IDS_BLOCK ",
		"--nflog-threshold", "1",
	}
}

// outboundNFLOGArgs returns rule args for the OUTPUT chain.
// Port-filtered so we only capture traffic to suspicious C2/exfil ports.
// The rule fires BEFORE UFW drops the packet, giving us visibility into
// connection attempts regardless of whether the firewall blocks them.
func outboundNFLOGArgs(proto string) []string {
	return []string{
		"-p", proto,
		"-m", "multiport", "--dports", suspiciousOutboundPorts,
		"-j", "NFLOG",
		"--nflog-group", fmt.Sprintf("%d", nflogGroup),
		"--nflog-prefix", "IDS_BLOCK ",
		"--nflog-threshold", "1",
	}
}

// nflogInboundChains4/6 are the UFW logging chains on the INPUT/FORWARD path.
var nflogInboundChains4 = []string{"ufw-logging-deny", "ufw-after-logging-input"}
var nflogInboundChains6 = []string{"ufw6-logging-deny", "ufw6-after-logging-input"}

// runIPTables executes an iptables command and logs the result.
// Returns true on success.
func runIPTables(args []string) bool {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		log.Printf("NFLOGCollector: iptables warning %v: %v — %s", args, err, out)
		return false
	}
	log.Printf("NFLOGCollector: iptables OK: %v", args)
	return true
}

// ruleExists uses iptables -C to check whether a specific rule is present
// in chain.  Returns true if present, false if not.
// Takes explicit ruleArgs so the same function works for both inbound and
// outbound rules which have different match criteria.
func ruleExists(ipt, chain string, ruleArgs []string) bool {
	args := append([]string{ipt, "-C", chain}, ruleArgs...)
	return exec.Command(args[0], args[1:]...).Run() == nil
}

// insertRuleAtHead adds a rule at position 1 of chain if it isn't already there.
func insertRuleAtHead(ipt, chain string, ruleArgs []string) {
	if ruleExists(ipt, chain, ruleArgs) {
		return
	}
	args := append([]string{ipt, "-I", chain, "1"}, ruleArgs...)
	runIPTables(args)
}

// deleteRuleBySpec removes a rule by content match, not by position.
// This prevents accidentally deleting a UFW rule that drifted to position 1.
func deleteRuleBySpec(ipt, chain string, ruleArgs []string) {
	if !ruleExists(ipt, chain, ruleArgs) {
		return
	}
	args := append([]string{ipt, "-D", chain}, ruleArgs...)
	runIPTables(args)
}

// setup inserts all NFLOG rules.
//
// Inbound: hooks into UFW's logging chains — catches all inbound/forward
// denied packets before UFW's burst-limited LOG target.
//
// Outbound: hooks into the OUTPUT chain for specific suspicious ports.
// UFW's outbound deny rules sit in ufw-user-output and DROP packets there —
// ufw-logging-deny is never called for outbound so we must hook OUTPUT
// directly.  The NFLOG rule fires first, then UFW drops the packet.
func (c *NFLOGCollector) setup() {
	log.Println("NFLOGCollector: inserting inbound NFLOG rules")
	inArgs := inboundNFLOGArgs()
	for _, chain := range nflogInboundChains4 {
		insertRuleAtHead("iptables", chain, inArgs)
	}
	for _, chain := range nflogInboundChains6 {
		insertRuleAtHead("ip6tables", chain, inArgs)
	}

	log.Println("NFLOGCollector: inserting outbound NFLOG rules into OUTPUT chain")
	for _, proto := range []string{"tcp", "udp"} {
		insertRuleAtHead("iptables", "OUTPUT", outboundNFLOGArgs(proto))
	}
}

// teardown removes all NFLOG rules using rule-spec deletion.
func (c *NFLOGCollector) teardown() {
	log.Println("NFLOGCollector: removing NFLOG rules")
	inArgs := inboundNFLOGArgs()
	for _, chain := range nflogInboundChains4 {
		deleteRuleBySpec("iptables", chain, inArgs)
	}
	for _, chain := range nflogInboundChains6 {
		deleteRuleBySpec("ip6tables", chain, inArgs)
	}
	for _, proto := range []string{"tcp", "udp"} {
		deleteRuleBySpec("iptables", "OUTPUT", outboundNFLOGArgs(proto))
	}
	log.Println("NFLOGCollector: teardown complete")
}

// watchRules re-inserts any NFLOG rules that UFW wiped during a reload.
// UFW flushes its own chains (ufw-*) on every rule change, removing our
// inbound hooks.  The OUTPUT chain rules survive ufw reload but not
// iptables -F OUTPUT, so we watch those too.
func (c *NFLOGCollector) watchRules(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			inArgs := inboundNFLOGArgs()
			for _, chain := range nflogInboundChains4 {
				if !ruleExists("iptables", chain, inArgs) {
					log.Printf("NFLOGCollector: inbound NFLOG rule missing from %s — re-inserting", chain)
					insertRuleAtHead("iptables", chain, inArgs)
				}
			}
			for _, chain := range nflogInboundChains6 {
				if !ruleExists("ip6tables", chain, inArgs) {
					log.Printf("NFLOGCollector: inbound NFLOG rule missing from %s — re-inserting", chain)
					insertRuleAtHead("ip6tables", chain, inArgs)
				}
			}
			for _, proto := range []string{"tcp", "udp"} {
				outArgs := outboundNFLOGArgs(proto)
				if !ruleExists("iptables", "OUTPUT", outArgs) {
					log.Printf("NFLOGCollector: outbound NFLOG rule missing for proto %s — re-inserting", proto)
					insertRuleAtHead("iptables", "OUTPUT", outArgs)
				}
			}
		}
	}
}

// ── Collector entry point ──────────────────────────────────────────────────

// Start opens the NFLOG socket, inserts iptables rules, then blocks until
// ctx is cancelled.  Must be called in a goroutine.
//
// IMPORTANT: main() must wait for this goroutine to finish before exiting —
// see the WaitGroup usage in main.go — otherwise the process exits before
// defer teardown() can remove the iptables rules.
func (c *NFLOGCollector) Start(ctx context.Context, out chan<- *model.NormalizedEvent) {
	// Open the netlink socket BEFORE inserting iptables rules.
	// If rules are inserted first, packets that arrive before the socket is
	// ready are silently discarded by the kernel.
	cfg := nflog.Config{
		Group:    nflogGroup,
		Copymode: nflog.CopyPacket,
	}

	nf, err := nflog.Open(&cfg)
	if err != nil {
		log.Fatalf("NFLOGCollector: failed to open nflog socket: %v", err)
	}
	defer nf.Close()

	log.Printf("NFLOGCollector: netlink socket open on group %d", nflogGroup)

	// Insert iptables rules now that the socket is ready to receive.
	c.setup()
	// Always remove the rules when we exit — even on panic or fatal error.
	defer c.teardown()

	// Watch for UFW reloads that silently wipe our NFLOG rules.
	// UFW rebuilds its chains on every rule change — this goroutine detects
	// that and re-inserts our rules within 30 seconds of a reload.
	go c.watchRules(ctx)

	hook := func(attrs nflog.Attribute) int {
		event := parseNFLOGPacket(attrs)
		if event == nil {
			// Non-IPv4 or malformed — skip silently.
			return 0
		}

		log.Printf("NFLOGCollector: [%s] src=%s port=%s proto=%s",
			event.EventType, event.SourceIP, event.Port, event.Command)
		if c.Stats != nil {
			c.Stats.RecordLine(event.LogSource)
		}
		if c.Broadcaster != nil {
			c.Broadcaster.Publish(event.LogSource, event.RawLine)
		}

		select {
		case out <- event:
		case <-ctx.Done():
			return 1
		}
		return 0
	}

	errFn := func(err error) int {
		if ctx.Err() != nil {
			return 1 // context cancelled — not an error
		}
		log.Println("NFLOGCollector: nflog error:", err)
		return 0
	}

	log.Println("NFLOGCollector: registering packet hook")
	if err := nf.RegisterWithErrorFunc(ctx, hook, errFn); err != nil {
		if ctx.Err() == nil {
			log.Fatalf("NFLOGCollector: register failed: %v", err)
		}
	}
	log.Println("NFLOGCollector: ready — waiting for packets")

	// RegisterWithErrorFunc is non-blocking — block here to keep both the
	// goroutine and the nflog socket alive until context cancellation.
	// Without this, defer nf.Close() fires immediately and the errFn loops
	// endlessly with "bad file descriptor".
	<-ctx.Done()
	log.Println("NFLOGCollector: context cancelled — shutting down")
}

// ── Packet parser ──────────────────────────────────────────────────────────

func parseNFLOGPacket(attrs nflog.Attribute) *model.NormalizedEvent {
	if attrs.Payload == nil {
		return nil
	}
	pkt := *attrs.Payload

	if len(pkt) < 20 {
		return nil
	}
	version := pkt[0] >> 4
	if version != 4 {
		return nil
	}

	ihl := int(pkt[0]&0x0f) * 4
	if len(pkt) < ihl {
		return nil
	}

	proto := pkt[9]
	srcIP := net.IP(pkt[12:16]).String()
	dstIP := net.IP(pkt[16:20]).String()

	var srcPort, dstPort uint16
	var protoName string

	switch proto {
	case 6: // TCP
		if len(pkt) < ihl+4 {
			return nil
		}
		srcPort = binary.BigEndian.Uint16(pkt[ihl : ihl+2])
		dstPort = binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
		protoName = "TCP"

	case 17: // UDP
		if len(pkt) < ihl+4 {
			return nil
		}
		srcPort = binary.BigEndian.Uint16(pkt[ihl : ihl+2])
		dstPort = binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
		protoName = "UDP"

	case 1: // ICMP
		protoName = "ICMP"

	default:
		return nil
	}

	eventType := "FW_BLOCK"
	if (attrs.InDev == nil || *attrs.InDev == 0) &&
		(attrs.OutDev != nil && *attrs.OutDev != 0) {
		eventType = "FW_BLOCK_OUT"
	}

	ts := time.Now()
	if attrs.Timestamp != nil {
		ts = *attrs.Timestamp
	}

	rawLine := fmt.Sprintf(
		"[NFLOG] %s SRC=%s DST=%s PROTO=%s SPT=%d DPT=%d",
		eventType, srcIP, dstIP, protoName, srcPort, dstPort,
	)

	return &model.NormalizedEvent{
		Timestamp:  ts,
		LogSource:  "ufw",
		Program:    "kernel",
		EventType:  eventType,
		SourceIP:   srcIP,
		Port:       fmt.Sprintf("%d", dstPort),
		Command:    protoName,
		Message:    rawLine,
		RawLine:    rawLine,
		EventCount: 1,
	}
}
