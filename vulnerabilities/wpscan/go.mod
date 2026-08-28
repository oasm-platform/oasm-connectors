module github.com/open-asm/oasm-connectors/vulnerabilities/wpscan

go 1.26

require github.com/open-asm/oasm-connectors/sdk v0.0.0

require (
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/grpc v1.83.1 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace github.com/open-asm/oasm-connectors/sdk => ../../sdk
