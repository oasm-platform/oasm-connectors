package connector

import (
	"context"
	"strings"
	"testing"
)

type sampleConfig struct {
	Rate  int    `json:"rate"`
	Ports string `json:"ports"`
}

func TestLoadConfigPrefersContextOverEnv(t *testing.T) {
	t.Setenv("OASM_CONFIG", `{"rate":5}`)
	ctx := WithConfig(context.Background(), `{"rate":42}`)
	cfg, err := LoadConfig[sampleConfig](ctx)
	if err != nil || cfg.Rate != 42 {
		t.Fatalf("got %+v, %v; want rate 42 from ctx", cfg, err)
	}
}

func TestLoadConfigFallsBackToEnv(t *testing.T) {
	t.Setenv("OASM_CONFIG", `{"rate":5,"ports":"22"}`)
	cfg, err := LoadConfig[sampleConfig](context.Background())
	if err != nil || cfg.Rate != 5 || cfg.Ports != "22" {
		t.Fatalf("got %+v, %v; want env config", cfg, err)
	}
}

func TestLoadConfigEmptyContextValueFallsBackToEnv(t *testing.T) {
	t.Setenv("OASM_CONFIG", `{"rate":5}`)
	cfg, err := LoadConfig[sampleConfig](WithConfig(context.Background(), "  "))
	if err != nil || cfg.Rate != 5 {
		t.Fatalf("got %+v, %v; blank ctx config must not mask env", cfg, err)
	}
}

func TestLoadConfigUnsetYieldsZeroValue(t *testing.T) {
	t.Setenv("OASM_CONFIG", "")
	cfg, err := LoadConfig[sampleConfig](context.Background())
	if err != nil || cfg == nil || *cfg != (sampleConfig{}) {
		t.Fatalf("got %+v, %v; want non-nil zero config", cfg, err)
	}
}

func TestLoadConfigMalformedJSONFails(t *testing.T) {
	_, err := LoadConfig[sampleConfig](WithConfig(context.Background(), `{bad`))
	if err == nil || !strings.Contains(err.Error(), "invalid OASM_CONFIG") {
		t.Fatalf("err = %v, want invalid OASM_CONFIG", err)
	}
}
