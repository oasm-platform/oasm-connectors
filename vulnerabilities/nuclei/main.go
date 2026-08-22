package main

import (
	"context"
	"log"
	"os"

	sdkconn "github.com/open-asm/oasm-connectors/sdk/connector"
	"github.com/open-asm/oasm-connectors/sdk/runtime"
)

func main() {
	adapter := &NucleiAdapter{}
	_ = os.Getenv("NUCLEI_BIN") // ponytail: BinPath wiring when exec is added; kept for parity with spec sketch
	conn := sdkconn.New(adapter)
	rt := runtime.New(conn)
	// ponytail: real main would Dial worker via transport.Dial + lifecycle Connect/Ready/Run with signal handling
	_ = rt
	if err := rt.Run(context.Background()); err != nil && err != context.Canceled {
		log.Printf("runtime error: %v", err)
		os.Exit(1)
	}
}
