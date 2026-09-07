package main

// deps.go pins the nuclei SDK module until adapter.go imports it for real (deleted in T4).
import (
	_ "github.com/projectdiscovery/nuclei/v3/lib"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/output"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/installer"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
)