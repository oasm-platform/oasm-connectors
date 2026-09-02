package main

import (
	"context"
	"log"

	sdkconn "github.com/oasm-platform/oasm-connectors/sdk/connector"
	"github.com/oasm-platform/oasm-connectors/sdk/runtime"
)

func main() {
	adapter := &NessusAdapter{}
	conn := sdkconn.New(adapter)
	rt := runtime.New(conn)

	log.Println("nessus connector starting...")
	if err := rt.Run(context.Background()); err != nil && err != context.Canceled {
		log.Fatalf("connector failed: %v", err)
	}
	log.Println("nessus connector stopped")
}
