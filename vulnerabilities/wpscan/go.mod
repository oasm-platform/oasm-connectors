module github.com/oasm-platform/oasm-connectors/vulnerabilities/wpscan

go 1.26.0

require github.com/oasm-platform/oasm-connectors/sdk v0.0.0

require (
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/text v0.44.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260825221802-da73d73af1c5 // indirect
	google.golang.org/grpc v1.85.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace github.com/oasm-platform/oasm-connectors/sdk => ../../sdk
