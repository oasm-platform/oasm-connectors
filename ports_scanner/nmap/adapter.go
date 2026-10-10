package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// nmapHardTimeout bounds the whole nmap process. The manifest's
// resourceDefaults.timeoutSeconds (1800s) sits above it so the adapter reports
// a clean "timed out after 20m0s" error before the container is killed.
const nmapHardTimeout = 20 * time.Minute

// nmapXML is the slice of nmap's XML output (-oX -) the adapter consumes. Only
// the fields needed to build a Finding are modelled; anything else nmap emits
// (scripts, traces, timing) is ignored by encoding/xml rather than parsed.
type nmapXML struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
	} `xml:"hostnames>hostname"`
	Ports []struct {
		Protocol string `xml:"protocol,attr"`
		PortID   string `xml:"portid,attr"`
		State    struct {
			State string `xml:"state,attr"`
		} `xml:"state"`
		Service struct {
			Name    string `xml:"name,attr"`
			Product string `xml:"product,attr"`
			Version string `xml:"version,attr"`
			Extra   string `xml:"extrainfo,attr"`
		} `xml:"service"`
	} `xml:"ports>port"`
}

// NmapAdapter runs nmap (github.com/nmap/nmap) and streams one
// connector.Finding per OPEN port (Severity=info, Name="open tcp/443 (https)",
// MatchedAt=host:port, Host=target, IP=resolved address, Ports=[port]).
//
// Closed and filtered ports are deliberately dropped: the catalogue's port view
// consumes the open set, and emitting "closed" noise would be thousands of
// findings per job.
type NmapAdapter struct{}

// Validate rejects malformed inputs/cfg before any process or network resource
// is spent. It is pure: no DNS, no socket.
func (a NmapAdapter) Validate(ctx context.Context, inputs map[string]any) error {
	if _, err := connector.SingleHost(inputs); err != nil {
		return err
	}
	cfg, err := connector.LoadConfig[nmapConfig](ctx)
	if err != nil {
		return err
	}
	if cfg.Ports != "" && !validPortSpec(cfg.Ports) {
		return fmt.Errorf("invalid ports %q (digits, commas and hyphens only)", cfg.Ports)
	}
	if cfg.TopPorts < 0 || cfg.HostTimeout < 0 || cfg.Retries < 0 {
		return fmt.Errorf("invalid nmap config: counts must not be negative")
	}
	return nil
}

// Execute runs nmap in XML mode and streams one Finding per open port.
//
// Exit-code semantics: nmap exits 0 whenever the scan completed, even when
// every host was down or every port was closed (a clean, zero-findings run).
// A nonzero exit means nmap itself failed (bad flag, unresolvable target) and
// is a retryable error; the stderr tail goes with it.
func (a NmapAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	target, err := connector.SingleHost(inputs)
	if err != nil {
		return err
	}

	cfg, err := connector.LoadConfig[nmapConfig](ctx)
	if err != nil {
		return err
	}
	if cfg.Ports != "" && !validPortSpec(cfg.Ports) {
		return fmt.Errorf("invalid ports %q (digits, commas and hyphens only)", cfg.Ports)
	}

	bin := os.Getenv("NMAP_BIN")
	if bin == "" {
		bin = "nmap"
	}

	// Resolve once so every finding carries the scanned address: the catalogue's
	// ports_scanner data source is the asset, and an unparseable address would
	// cost the finding its attribution. An unresolvable target is fatal — nmap
	// would only fail a few seconds later with a less specific error.
	ip := connector.ResolveIPv4(target)
	if ip == "" {
		return fmt.Errorf("fatal: nmap: cannot resolve %q", target)
	}

	runCtx, cancel := context.WithTimeout(ctx, nmapHardTimeout)
	defer cancel()

	stderr := connector.NewTailWriter(2048)

	// -n is paired with the resolution above: nmap is handed an address, so it
	// never re-resolves and never emits PTR noise to stderr.
	cmd := exec.CommandContext(runCtx, bin, buildNmapArgs(ip, cfg)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("nmap: stdout pipe: %w", err)
	}
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("nmap: start: %w", err)
	}

	emitted := 0
	var parseErr error
	if hosts, err := parseNmapXML(stdout); err != nil {
		parseErr = err
	} else {
		for i := range hosts {
			for _, p := range hosts[i].Ports {
				if !strings.EqualFold(p.State.State, "open") {
					continue
				}
				f := openPortFinding(target, ip, p.Protocol, p.PortID, p.Service.Name, p.Service.Product, p.Service.Version, p.Service.Extra)
				select {
				case <-ctx.Done():
					_ = cmd.Wait()
					return ctx.Err()
				case <-runCtx.Done():
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
					return fmt.Errorf("nmap: timed out after %s", nmapHardTimeout)
				case out <- f:
					emitted++
				}
			}
		}
	}

	waitErr := cmd.Wait()
	tail := stderr.String()

	if ctx.Err() != nil {
		return ctx.Err()
	}
	if runCtx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("nmap: timed out after %s", nmapHardTimeout)
	}
	if waitErr != nil && emitted == 0 {
		if tail != "" {
			return fmt.Errorf("retryable: nmap: %w: %s", waitErr, tail)
		}
		return fmt.Errorf("retryable: nmap: %w", waitErr)
	}
	if parseErr != nil {
		// A clean exit with an unreadable document (or one that died mid-stream)
		// ships the ports already emitted and reports the truncation.
		return fmt.Errorf("retryable: nmap: reading output: %v", parseErr)
	}
	return nil
}

// parseNmapXML decodes nmap's -oX stream. Trailing garbage after the document
// (nmap never emits any) is ignored by the decoder, so a complete document is a
// complete parse.
func parseNmapXML(r io.Reader) ([]nmapHost, error) {
	var doc nmapXML
	if err := xml.NewDecoder(r).Decode(&doc); err != nil {
		return nil, err
	}
	return doc.Hosts, nil
}

// openPortFinding maps one nmap open port onto the connector contract. Name
// stays stable and greppable ("open tcp/443 (https)") so the dashboard's port
// view can group by protocol/service without re-parsing descriptions.
func openPortFinding(target, ip, proto, portID, service, product, version, extra string) connector.Finding {
	if proto == "" {
		proto = "tcp"
	}
	endpoint := portString(proto, portID)
	name := "open " + endpoint
	if service != "" {
		name += " (" + service + ")"
	}
	tags := []string{"port", proto}
	for _, v := range []string{service, product, version, extra} {
		if v != "" {
			tags = append(tags, v)
		}
	}
	return connector.Finding{
		Name:      name,
		Severity:  "info",
		MatchedAt: target + ":" + portID,
		Host:      target,
		IP:        ip,
		Ports:     []string{endpoint},
		Tags:      tags,
		Timestamp: time.Now(),
	}
}

// portString renders "tcp/443" from nmap's separate protocol/portid attributes.
func portString(proto, portID string) string { return proto + "/" + portID }
