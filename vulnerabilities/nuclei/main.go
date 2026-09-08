package main

import (
	"context"
	"log"

	sdkconn "github.com/oasm-platform/oasm-connectors/sdk/connector"
	"github.com/oasm-platform/oasm-connectors/sdk/runtime"
)

func main() {
	adapter := &NucleiAdapter{} // in-process nuclei SDK engine (github.com/projectdiscovery/nuclei/v3/lib)
	conn := sdkconn.New(adapter)
	rt := runtime.New(conn)

	log.Println("nuclei connector starting...")
	if err := rt.Run(context.Background()); err != nil && err != context.Canceled {
		log.Fatalf("connector failed: %v", err)
	}
	log.Println("nuclei connector stopped")
}
