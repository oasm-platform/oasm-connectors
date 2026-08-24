package main

import (
	"context"
	"log"

	sdkconn "github.com/open-asm/oasm-connectors/sdk/connector"
	"github.com/open-asm/oasm-connectors/sdk/runtime"
)

func main() {
	adapter := WpscanAdapter{}
	conn := sdkconn.New(adapter)
	rt := runtime.New(conn)
	if err := rt.Run(context.Background()); err != nil {
		log.Fatalf("wpscan connector: %v", err)
	}
}
