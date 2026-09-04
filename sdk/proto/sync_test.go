package proto

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// field is one proto field: wire tag, type, name. Order is preserved because
// proto field numbers matter (wire compatibility), not just names.
type field struct {
	tag  int
	typ  string
	name string
}

var (
	messageRe = regexp.MustCompile(`^\s*message\s+([A-Za-z_]\w*)\s*\{`)
	// Handles scalar types (string, bool, bytes) and map<k, v> fields.
	fieldRe = regexp.MustCompile(`^\s*((?:map\s*<\s*[\w.]+\s*,\s*[\w.]+\s*>)|[\w.]+)\s+([A-Za-z_]\w*)\s*=\s*(\d+)\s*;`)
	rpcRe   = regexp.MustCompile(`^\s*rpc\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*returns\s*\(([^)]*)\)\s*;`)
)

// parseProto extracts, per message, the ordered field list, plus RPC
// signatures, using a minimal text parse of the proto3 subset used by
// connector.proto. Oneof members are recorded as fields of the enclosing
// message (they share its wire layout). Comments are ignored.
func parseProto(path string) (map[string][]field, []string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	msgs := make(map[string][]field)
	var rpcs []string
	cur := ""
	for _, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if m := messageRe.FindStringSubmatch(trimmed); m != nil {
			cur = m[1]
			continue
		}
		if m := rpcRe.FindStringSubmatch(trimmed); m != nil {
			rpcs = append(rpcs, m[1]+"("+strings.Join(strings.Fields(m[2]), " ")+") returns ("+strings.Join(strings.Fields(m[3]), " ")+")")
			continue
		}
		if cur != "" {
			if m := fieldRe.FindStringSubmatch(trimmed); m != nil {
				tag, err := strconv.Atoi(m[3])
				if err != nil {
					return nil, nil, fmt.Errorf("%s: bad field tag %q: %w", path, m[3], err)
				}
				msgs[cur] = append(msgs[cur], field{tag: tag, typ: m[1], name: m[2]})
			}
		}
	}
	return msgs, rpcs, nil
}

// requiredMessages are the wire-critical message definitions shared between
// the SDK (sdk/proto/connector.proto) and the worker
// (worker/internal/proto/connector.proto). ConnectorMessage/WorkerMessage are
// the oneof wrappers that carry them on the Connect stream.
var requiredMessages = []string{"Register", "RegisterAck", "ExecuteJob", "Cancel", "Result", "Done", "ConnectorMessage", "WorkerMessage"}

// TestConnectorProtoSyncedWithWorker guards the double-source of
// connector.proto. The SDK's proto and the worker's copy must stay identical
// at the wire level; drift means the two sides speak different protocols.
func TestConnectorProtoSyncedWithWorker(t *testing.T) {
	sdkPath := "connector.proto"
	workerPath := os.Getenv("OASM_WORKER_PROTO")
	if workerPath == "" {
		workerPath = filepath.Join("..", "..", "..", "open-asm", "worker", "internal", "proto", "connector.proto")
	}

	sdkMsgs, sdkRpcs, err := parseProto(sdkPath)
	if err != nil {
		t.Fatalf("parse %s: %v", sdkPath, err)
	}
	workerMsgs, workerRpcs, err := parseProto(workerPath)
	if err != nil {
		t.Fatalf("parse %s (required to verify sync): %v", workerPath, err)
	}

	var diffs []string
	diff := func(format string, args ...any) { diffs = append(diffs, fmt.Sprintf(format, args...)) }

	for _, name := range requiredMessages {
		sdkFields, sdkOK := sdkMsgs[name]
		workerFields, workerOK := workerMsgs[name]
		switch {
		case !sdkOK && !workerOK:
			diff("message %s: missing on BOTH sides", name)
		case !sdkOK:
			diff("message %s: present in worker, missing in sdk", name)
		case !workerOK:
			diff("message %s: present in sdk, missing in worker", name)
		case !reflect.DeepEqual(sdkFields, workerFields):
			diff("message %s:\n  sdk:    %v\n  worker: %v", name, sdkFields, workerFields)
		}
	}

	if len(sdkRpcs) != len(workerRpcs) {
		diff("rpc count: sdk=%v worker=%v", sdkRpcs, workerRpcs)
	} else {
		for i := range sdkRpcs {
			if sdkRpcs[i] != workerRpcs[i] {
				diff("rpc #%d:\n  sdk:    %s\n  worker: %s", i, sdkRpcs[i], workerRpcs[i])
			}
		}
	}

	if len(diffs) > 0 {
		t.Fatalf("proto double-source desync: sửa cả 2 nơi (sdk/proto/connector.proto và worker/internal/proto/connector.proto), xem worker/internal/proto/connector.proto\n%s",
			strings.Join(diffs, "\n"))
	}
}
