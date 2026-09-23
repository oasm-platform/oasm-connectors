package main

import (
	"context"
	"log"

	sdkconn "github.com/oasm-platform/oasm-connectors/sdk/connector"
	"github.com/oasm-platform/oasm-connectors/sdk/runtime"
)

func main() {
	adapter := &OpenVASAdapter{}
	conn := sdkconn.New(adapter)
	rt := runtime.New(conn)

	log.Println("openvas connector starting...")
	if err := rt.Run(context.Background()); err != nil && err != context.Canceled {
		log.Fatalf("connector failed: %v", err)
	}
	log.Println("openvas connector stopped")
}
