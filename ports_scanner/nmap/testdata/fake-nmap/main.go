package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// fake-nmap is a stand-in for the nmap CLI used by adapter tests. It mirrors the
// real binary's contract: nmap XML on stdout (-oX -), diagnostics on stderr, and
// exit 0 for any completed scan — including a host with no open ports.
func main() {
	// Capture the exact arg vector the adapter passed so tests can assert on it.
	// This must not alter FAKE_MODE behavior.
	if argsFile := os.Getenv("FAKE_ARGS_FILE"); argsFile != "" {
		raw, err := json.Marshal(os.Args[1:])
		if err != nil {
			fmt.Fprintln(os.Stderr, "marshal args:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(argsFile, raw, 0644); err != nil {
			fmt.Fprintln(os.Stderr, "write args:", err)
			os.Exit(1)
		}
	}

	switch os.Getenv("FAKE_MODE") {
	case "empty":
		// Scan completed, every port closed/filtered: exit 0, no findings.
		fmt.Print(hostXML(`<ports><port protocol="tcp" portid="22"><state state="closed" reason="resets" reason_ttl="0"/><service name="ssh" method="table" conf="3"/></port></ports>`))
		os.Exit(0)
	case "fail":
		// nmap itself failed (bad flag / unresolvable): stderr only, exit 1.
		fmt.Fprintln(os.Stderr, "nmap: unrecognized option '--bogus'")
		os.Exit(1)
	case "partial":
		// A truncated document: the adapter must report the read error, not
		// silently return the ports it happened to see.
		fmt.Print(`<?xml version="1.0"?><nmaprun><host><ports><port protocol="tcp" portid="80"`)
		os.Exit(0)
	case "hang":
		// Simulates nmap wedging; the adapter's hard timeout must kill it.
		time.Sleep(60 * time.Second)
		os.Exit(0)
	default:
		fmt.Print(hostXML(
			`<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="64"/>` +
				`<service name="http" product="nginx" version="1.27.0" extrainfo="Ubuntu" method="probed" conf="10"/></port>` +
				`<port protocol="tcp" portid="443"><state state="open" reason="syn-ack" reason_ttl="64"/>` +
				`<service name="https" product="nginx" version="1.27.0" tunnel="ssl" method="probed" conf="10"/></port>` +
				`<port protocol="tcp" portid="8080"><state state="filtered" reason="no-response" reason_ttl="0"/></port>` +
				`<port protocol="udp" portid="53"><state state="open" reason="udp-response" reason_ttl="64"/>` +
				`<service name="domain" method="probed" conf="10"/></port>`,
		))
		os.Exit(0)
	}
}

// hostXML wraps port elements in the minimal nmaprun document nmap emits for a
// single -Pn target: one host, one resolved address, one hostname.
func hostXML(ports string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` +
		`<!DOCTYPE nmaprun>` +
		`<nmaprun scanner="nmap" args="nmap -Pn -n -oX - 127.0.0.1" start="1" startstr="x" version="7.97" xmloutputversion="1.05">` +
		`<host starttime="1" endtime="2"><status state="up" reason="user-set"/>` +
		`<address addr="127.0.0.1" addrtype="ipv4"/>` +
		`<hostnames><hostname name="localhost" type="PTR"/></hostnames>` +
		`<ports>` + ports + `</ports>` +
		`</host>` +
		`<runstats><finished time="2" timestr="x" elapsed="0.01" summary="Nmap done" exit="success"/></runstats>` +
		`</nmaprun>`
}
