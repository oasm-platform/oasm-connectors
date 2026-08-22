package main

import (
	"context"
	"encoding/json"
	"testing"
)

func TestNucleiValidate_AcceptsValidTarget(t *testing.T) {
	a := &NucleiAdapter{}
	if err := a.Validate(context.Background(), map[string]any{"target": "https://example.com"}); err != nil {
		t.Fatalf("expected no error for valid target, got %v", err)
	}
}

func TestNucleiValidate_RejectsMissingTarget(t *testing.T) {
	a := &NucleiAdapter{}
	if err := a.Validate(context.Background(), map[string]any{}); err == nil {
		t.Fatal("expected error for missing target")
	}
	if err := a.Validate(context.Background(), map[string]any{"target": ""}); err == nil {
		t.Fatal("expected error for empty target")
	}
}

func TestNucleiExecute_EmitsFindingWithTemplateIDAndMatchedAt(t *testing.T) {
	a := &NucleiAdapter{}
	ch := make(chan []byte, 4)
	target := "https://example.com"
	if err := a.Execute(context.Background(), map[string]any{"target": target}, ch); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	select {
	case got := <-ch:
		var m map[string]any
		if err := json.Unmarshal(got, &m); err != nil {
			t.Fatalf("output not valid JSON: %v (%s)", err, got)
		}
		if m["template-id"] == nil && m["templateID"] == nil {
			t.Fatalf("missing template-id: %s", got)
		}
		// accept either "template-id" or "templateID"
		tid := m["template-id"]
		if tid == nil {
			tid = m["templateID"]
		}
		if tid == "" {
			t.Fatalf("empty template-id: %s", got)
		}
		matched := m["matched-at"]
		if matched == nil {
			matched = m["matchedAt"]
		}
		if matched != target {
			t.Fatalf("matched-at mismatch: want %q got %v (%s)", target, matched, got)
		}
		// severity should be present inside info.severity
		if info, ok := m["info"].(map[string]any); ok {
			if info["severity"] == nil || info["severity"] == "" {
				t.Fatalf("missing info.severity: %s", got)
			}
		} else {
			t.Fatalf("missing info object: %s", got)
		}
	default:
		t.Fatal("no output emitted")
	}
}
