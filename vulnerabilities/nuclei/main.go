package main

import (
	"context"
	"log"

	sdkconn "github.com/open-asm/oasm-connectors/sdk/connector"
	"github.com/open-asm/oasm-connectors/sdk/runtime"
)

func main() {
	adapter := &NucleiAdapter{} // binary path comes from NUCLEI_BIN at Execute time
	conn := sdkconn.New(adapter)
	rt := runtime.New(conn)

	log.Println("nuclei connector starting...")
	if err := rt.Run(context.Background()); err != nil && err != context.Canceled {
		log.Fatalf("connector failed: %v", err)
	}
	log.Println("nuclei connector stopped")
}
