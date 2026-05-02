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

// ── iptables lifecycle ─────────────────────────────────────────────────────

func iptablesArgs(op string) [][]string {
	nflogArgs := []string{
		"-j", "NFLOG",
		"--nflog-group", fmt.Sprintf("%d", nflogGroup),
		"--nflog-prefix", "IDS_BLOCK ",
		"--nflog-threshold", "1",
	}
	return [][]string{
		// position "1" puts our rule before UFW's rate-limited LOG target
		append([]string{"iptables", op, "ufw-logging-deny", "1"}, nflogArgs...),
		append([]string{"ip6tables", op, "ufw6-logging-deny", "1"}, nflogArgs...),
	}
}

func runIPTables(args []string) {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		log.Printf("NFLOGCollector: iptables warning %v: %v — %s", args, err, out)
	} else {
		log.Printf("NFLOGCollector: iptables OK: %v", args)
	}
}

func (c *NFLOGCollector) setup() {
	log.Println("NFLOGCollector: inserting iptables NFLOG rules")

	chains4 := []string{
		"ufw-logging-deny",
		"ufw-after-logging-input",
	}

	for _, chain := range chains4 {
		runIPTables([]string{
			"iptables", "-I", chain, "1",
			"-j", "NFLOG",
			"--nflog-group", fmt.Sprintf("%d", nflogGroup),
			"--nflog-prefix", "IDS_BLOCK ",
			"--nflog-threshold", "1",
		})
	}
	chains6 := []string{
		"ufw6-logging-deny",
		"ufw6-after-logging-input",
	}
	for _, chain := range chains6 {
		runIPTables([]string{
			"ip6tables", "-I", chain, "1",
			"-j", "NFLOG",
			"--nflog-group", fmt.Sprintf("%d", nflogGroup),
			"--nflog-prefix", "IDS_BLOCK ",
			"--nflog-threshold", "1",
		})
	}
}

func (c *NFLOGCollector) teardown() {
	log.Println("NFLOGCollector: removing iptables NFLOG rules")

	chains4 := []string{
		"ufw-logging-deny",
		"ufw-after-logging-input",
	}

	for _, chain := range chains4 {
		runIPTables([]string{"iptables", "-D", chain, "1"})
	}

	chains6 := []string{
		"ufw6-logging-deny",
		"ufw6-after-logging-input",
	}

	for _, chain := range chains6 {
		runIPTables([]string{"ip6tables", "-D", chain, "1"})
	}

	log.Println("NFLOGCollector: teardown complete")
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
