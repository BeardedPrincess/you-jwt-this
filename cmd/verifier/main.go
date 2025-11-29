// Launches webservice for JWT verification
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/beardedprincess/you-jwt-this/internal/verifier"
)

const DEFAULT_ADDR = "127.0.0.1:8080"

func main() {
	mux := http.NewServeMux()
	_ = verifier.StartServer(mux)

	addr := os.Getenv("YJT_ADDR")
	if addr == "" {
		addr = DEFAULT_ADDR
		log.Printf("[INFO] Using default listener address at %s.\n\t...To override, set YJT_ADDR environment variable.\n\t   EXAMPLE: 'export YJT_ADDR=\"127.0.0.1:9090\"' will listen on TCP port 9090 on all available host IPs", addr)
	} else {
		log.Printf("[INFO] Verifier service listening on '%s'", addr)
	}

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
