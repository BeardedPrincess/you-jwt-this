package verifier

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/beardedprincess/you-jwt-this/internal/api"
)

type nonceEntry struct {
	Value     string
	ExpiresAt time.Time
	Used      bool
}

// Server holds a list of nonces in memory.
//
//	Future: this should be persisted somewhere (database/reddis?)
//	Bug Hunting?:  this is not a very thread safe way to deal with this, and may be a problem using async http requests (mutex needed?)
//
// TODO: no cleanup of this is implemented, bad guy could fill up all our memory and crash the server
type Server struct {
	nonces map[string]nonceEntry
}

// Called at runtime to initialize a new "Server" instance (i.e. session manager)
func StartServer(mux *http.ServeMux) *Server {
	srv := &Server{
		nonces: make(map[string]nonceEntry),
	}

	srv.registerRoutes(mux)

	return srv
}

func (s *Server) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/nonce", s.handleNonce)
	mux.HandleFunc("/verify", s.handleVerify)
}

func (s *Server) handleNonce(w http.ResponseWriter, r *http.Request) {
	resp := api.NonceResponse{ID: "foo", Value: "bar"}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	resp := api.AttestResponse{OK: true, Message: "alright, alright, alright"}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
