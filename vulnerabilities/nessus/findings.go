package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/tencat-dev/nessus-client-go/nessus"
)

const pluginWorkers = 8

type finding struct {
	PluginID         int      `json:"plugin_id"`
	PluginName       string   `json:"plugin_name"`
	Severity         string   `json:"severity"`
	SeverityScore    int      `json:"severity_score,omitempty"`
	Target           string   `json:"target"`
	Host             string   `json:"host"`
	AffectedURL      string   `json:"affected_url,omitempty"`
	Ports            []string `json:"ports,omitempty"`
	Description      string   `json:"description,omitempty"`
	Synopsis         string   `json:"synopsis,omitempty"`
	Solution         string   `json:"solution,omitempty"`
	CVSSScore        float64  `json:"cvss_score,omitempty"`
	CVSSVector       string   `json:"cvss_vector,omitempty"`
	VPRScore         float64  `json:"vpr_score,omitempty"`
	EPSSScore        float64  `json:"epss_score,omitempty"`
	References       []string `json:"references,omitempty"`
	CVEIDs           []string `json:"cve_ids,omitempty"`
	CWEIDs           []string `json:"cwe_ids,omitempty"`
	BIDIDs           []string `json:"bid_ids,omitempty"`
	IAVAIDs          []string `json:"iava_ids,omitempty"`
	PublicationDate  string   `json:"publication_date,omitempty"`
	ModificationDate string   `json:"modification_date,omitempty"`
}

func mapSeverity(severity int) string {
	switch severity {
	case 0:
		return "info"
	case 1:
		return "low"
	case 2:
		return "medium"
	case 3:
		return "high"
	case 4:
		return "critical"
	default:
		return "info"
	}
}

func mapPluginOutput(v *nessus.VulnerabilityResource, output *nessus.ScansPluginOutputResponse, target string) (*finding, error) {
	if output == nil || output.Info == nil {
		return nil, fmt.Errorf("nil plugin output for plugin %d", v.PluginID)
	}

	desc := output.Info.Plugindescription
	attr := desc.Pluginattributes

	f := &finding{
		PluginID:      v.PluginID,
		PluginName:    desc.Pluginname,
		Severity:      mapSeverity(desc.Severity),
		SeverityScore: desc.Severity,
		Target:        target,
		Description:   attr.Description,
		Synopsis:      attr.Synopsis,
		Solution:      attr.Solution,
	}

	// Ports — collect all keys from all outputs, de-duplicate, sort
	portSet := make(map[string]struct{})
	for _, o := range output.Outputs {
		for k := range o.Ports {
			portSet[k] = struct{}{}
		}
	}
	if len(portSet) > 0 {
		f.Ports = make([]string, 0, len(portSet))
		for k := range portSet {
			f.Ports = append(f.Ports, k)
		}
		sort.Strings(f.Ports)
	}

	// Host / AffectedURL from first port entry
	if len(output.Outputs) > 0 {
		for _, o := range output.Outputs {
			for _, v := range o.Ports {
				if portSlice, ok := v.([]any); ok && len(portSlice) > 0 {
					if portMap, ok := portSlice[0].(map[string]any); ok {
						if hostname, ok := portMap["hostname"].(string); ok {
							f.Host = hostname
							f.AffectedURL = hostname
							break
						}
					}
				}
			}
			if f.Host != "" {
				break
			}
		}
	}
	if f.Host == "" {
		f.Host = target
	}

	// CVSS — prefer cvss3 over base
	if attr.RiskInformation["cvss3_base_score"] != "" {
		if score, err := strconv.ParseFloat(attr.RiskInformation["cvss3_base_score"], 64); err == nil {
			f.CVSSScore = score
		}
		f.CVSSVector = attr.RiskInformation["cvss3_vector"]
	} else if attr.RiskInformation["cvss_base_score"] != "" {
		if score, err := strconv.ParseFloat(attr.RiskInformation["cvss_base_score"], 64); err == nil {
			f.CVSSScore = score
		}
		f.CVSSVector = attr.RiskInformation["cvss_vector"]
	}

	// VPR
	if attr.VPRScore != "" {
		if score, err := strconv.ParseFloat(attr.VPRScore, 64); err == nil {
			f.VPRScore = score
		}
	}

	// EPSS
	if attr.EPSSScore != "" {
		if score, err := strconv.ParseFloat(attr.EPSSScore, 64); err == nil {
			f.EPSSScore = score
		}
	}

	// References
	if len(attr.SeeAlso) > 0 {
		f.References = attr.SeeAlso
	}

	// RefInformation grouping
	for _, ref := range attr.RefInformation.Ref {
		vals := ref.Values.Value
		switch ref.Name {
		case "cve":
			f.CVEIDs = append(f.CVEIDs, vals...)
		case "cwe":
			f.CWEIDs = append(f.CWEIDs, vals...)
		case "bid", "cae":
			f.BIDIDs = append(f.BIDIDs, vals...)
		case "iava":
			f.IAVAIDs = append(f.IAVAIDs, vals...)
		}
	}

	// Dates
	if attr.VulnInformation.VulnPublicationDate != "" {
		if date, err := time.Parse("2006/01/02", attr.VulnInformation.VulnPublicationDate); err == nil {
			f.PublicationDate = date.UTC().Format(time.RFC3339)
		}
	}
	if attr.VulnInformation.PatchPublicationDate != "" {
		if date, err := time.Parse("2006/01/02", attr.VulnInformation.PatchPublicationDate); err == nil {
			f.ModificationDate = date.UTC().Format(time.RFC3339)
		}
	}

	return f, nil
}

func collectFindings(ctx context.Context, client *nessus.Client, r *nessus.ScansDetailsResponse, target string, out chan<- []byte) error {
	if r == nil || len(r.Vulnerabilities) == 0 {
		return nil
	}

	type result struct {
		finding *finding
		order   int
	}

	results := make([]result, len(r.Vulnerabilities))
	sem := make(chan struct{}, pluginWorkers)
	var wg sync.WaitGroup

	for i, v := range r.Vulnerabilities {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, vuln *nessus.VulnerabilityResource) {
			defer wg.Done()
			defer func() { <-sem }()

			output, err := client.ScansPluginOutput(
				&nessus.ScansPluginOutputPathParams{
					ScanID:   r.Info.ObjectID,
					PluginID: vuln.PluginID,
				},
				&nessus.ScansPluginOutputQuery{},
			)
			if err != nil {
				log.Printf("nessus: plugin %d: %v", vuln.PluginID, err)
				return
			}

			f, err := mapPluginOutput(vuln, output, target)
			if err != nil {
				log.Printf("nessus: plugin %d map: %v", vuln.PluginID, err)
				return
			}

			results[idx] = result{finding: f, order: idx}
		}(i, v)
	}

	wg.Wait()

	// Collect non-nil results and sort by PluginID
	var collected []*finding
	for _, r := range results {
		if r.finding != nil {
			collected = append(collected, r.finding)
		}
	}
	sort.Slice(collected, func(i, j int) bool {
		return collected[i].PluginID < collected[j].PluginID
	})

	for _, f := range collected {
		data, err := json.Marshal(f)
		if err != nil {
			log.Printf("nessus: marshal plugin %d: %v", f.PluginID, err)
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- data:
		}
	}

	return nil
}
