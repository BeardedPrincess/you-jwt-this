package verifier

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/beardedprincess/you-jwt-this/internal/api"

	"github.com/google/uuid"
)

const NONCE_VALIDITY = 300 // lifetime for a nonce (in seconds) before it's invalidated

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
	// Get some random bytes to use as the nonce value
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	nonceVal := base64.StdEncoding.EncodeToString(b)

	// Generate a GUID for the id (lookup value)
	id := uuid.NewString()

	s.nonces[id] = nonceEntry{
		Value:     nonceVal,
		ExpiresAt: time.Now().Add(NONCE_VALIDITY * time.Second),
		Used:      false,
	}

	resp := api.NonceResponse{ID: id, Value: nonceVal}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	// Read the JWT payload from the body
	body, err := io.ReadAll(r.Body)
	fmt.Println("Got: " + string(body))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		resp := api.AttestResponse{OK: false, Message: fmt.Sprintf("Bad Request, malformed or empty POST body: %v", err)}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}

	// Separate the JWT Header & Payload from the Signature
	parts := strings.SplitN(string(body), ".", 3)
	encJwt := parts[0] + "." + parts[1]
	encSig := parts[2]
	_ = encSig

	// TODO: Validate the JWT using the signature

	// Decode the JWT, and return it in JSON response (body)
	jwt := api.Jwt{}
	err = jwt.Decode(string(encJwt))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		resp := api.AttestResponse{OK: false, Message: fmt.Sprintf("Unable to Base64 Decode JWT Token: %v", err)}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}

	resp := api.AttestResponse{OK: true, Message: jwt.ToString()}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
