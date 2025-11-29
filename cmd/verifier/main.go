// Launches webservice for JWT verification
package main

import (
	"log"
	"net/http"

	"github.com/beardedprincess/you-jwt-this/internal/verifier"
)

func main() {
	mux := http.NewServeMux()
	_ = verifier.StartServer(mux)

	addr := "127.0.0.1:8080"

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}

}
