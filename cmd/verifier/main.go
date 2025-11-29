// Launches webservice for JWT verification
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/beardedprincess/you-jwt-this/internal/verifier"
)

func main() {
	mux := http.NewServeMux()
	_ = verifier.StartServer(mux)

	addr := os.Getenv("YJT_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
