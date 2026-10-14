package main

import "github.com/oasm-platform/oasm-connectors/sdk/runtime"

func main() { runtime.Main("trivy", TrivyAdapter{}) }
