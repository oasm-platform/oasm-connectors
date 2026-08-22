package main

import (
	"context"
	"log"
	"os"

	sdkconn "github.com/open-asm/oasm-connectors/sdk/connector"
	"github.com/open-asm/oasm-connectors/sdk/runtime"
)

func main() {
	adapter := &NucleiAdapter{} // binary path comes from NUCLEI_BIN at Execute time
	conn := sdkconn.New(adapter)
	rt := runtime.New(conn)
	// ponytail: real main would Dial worker via transport.Dial + lifecycle Connect/Ready/Run with signal handling
	_ = rt
	if err := rt.Run(context.Background()); err != nil && err != context.Canceled {
		log.Printf("runtime error: %v", err)
		os.Exit(1)
	}
}
