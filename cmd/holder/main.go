// The holder will operate in 3 steps:
//  1. Load an existing key from YJT_KEYFILE, or, if it doesn't exist, generate one
//  1. Get a nonce value from the verifier server (/nonce)
//  2. Include the nonce as a value in the payload, and submit to the verifier (/verify)
//
//  The server will prevent reuse of the nonce, so a new one must be fetched for each submission

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/beardedprincess/you-jwt-this/internal/api"
	"github.com/beardedprincess/you-jwt-this/internal/crypto"
)

const DEFAULT_ADDR = "127.0.0.1:8080"
const DEFAULT_KEYFILE = "keyfile.jwk"

func main() {
	addr := os.Getenv("YJT_ADDR")
	if addr == "" {
		addr = DEFAULT_ADDR
		log.Printf("[INFO] Using default verifier address at %s.\n\t...To override, set YJT_ADDR environment variable.\n\t   EXAMPLE: 'export YJT_ADDR=\"127.0.0.1:9090\"' will connect to verifier on TCP port 9090 at 127.0.0.1", addr)
	} else {
		log.Printf("[INFO] Verifier service listening on '%s'", addr)
	}

	keyFile := os.Getenv("YJT_KEYFILE")
	if keyFile == "" {
		keyFile = DEFAULT_KEYFILE
		log.Printf("[INFO] Using default keyfile '%s'.\n\t...To override, set YJT_KEYFILE environment variable.\n\t   EXAMPLE: 'export YJT_KEYFILE=\"~/myOtherKey.jwk\"' to use a different key file (in JWK format)", keyFile)
	} else {
		log.Printf("[INFO] Will use '%s' for key operations", keyFile)
	}

	var pub ed25519.PublicKey
	var priv ed25519.PrivateKey // Using any since we don't know exactly what kind of key crypto will give us
	if _, err := os.Stat(keyFile); err == nil {
		log.Printf("[INFO] Loading key from existing file: '%s'", keyFile)
		pub, priv, err = crypto.LoadFromFile(keyFile)
		if err != nil {
			log.Fatalf("[FATAL] %v", err)
		}
	}

	if pub == nil || priv == nil {
		// Generate a keypair used to sign payload
		//. this function doesn't really care how "internal/crypto" handles this, or even what kind of key
		//. is generated/used. This is intentional to create extensibility / improvments later

		log.Printf("[INFO] Generating new key. It will be saved in %s", keyFile)
		var err error
		pub, priv, err = crypto.GenerateKey()
		if err != nil {
			log.Fatal(err)
		}
		crypto.SaveToFile(keyFile, pub, priv)
	}

	// TODO:  Figure out how to get the nonce from the serveer
	nonce, err := getNonce(fmt.Sprintf("http://%s/nonce", addr))
	if err != nil {
		log.Fatal(err)
	}

	// Testing invalid nonce
	// _ = nonce
	// nonce = &api.NonceResponse{ID: "afad", Value: "invalid"}

	// Testing expired nonce
	// time.Sleep((verifier.NONCE_VALIDITY + 2) * time.Second)

	// Testing already used nonce
	// nonce.ID = "ad685d8b-1b3a-48de-870a-476117c373cc"

	// Testing invalid value nonce
	// nonce.Value = "klfddklsad;klsadjklf;jlskdf;lkasdf;kl"

	// Construct the payload
	var jwt api.Jwt = api.Jwt{
		Header: api.Header{
			Type:      "JWT",
			Algorithm: "EdDSA",
		},
		Payload: api.Payload{
			Nonce:     *nonce,
			Subject:   "Lorem Ipsum",
			PublicKey: crypto.GetJWK(pub),
			Audience:  "https://you-jwt-this.beardedprincess.com",
		},
	}

	// Get the URL Encoded JWT
	encJwt := jwt.Encode()

	// Calculate the signature for the JWT && encode to Base64
	sig := base64.RawURLEncoding.EncodeToString(crypto.Sign(priv, []byte(encJwt)))

	// The full HEADER.PAYLOAD.SIGNATURE version of the JWT token, properly encoded (use JWT.io to verify works)
	strJwt := fmt.Sprintf("%s.%s", string(jwt.Encode()), string(sig))

	resp, err := checkVerify(fmt.Sprintf("http://%s/verify", addr), strJwt)
	if err != nil {
		log.Fatal(err)
	}

	// Marshal the response into pretty json for printing purposes
	bResp, err := json.Marshal(resp)
	if err != nil {
		log.Fatal(err)
	}
	strResp := string(bResp)

	fmt.Printf("\n------- Response from verifier service at %s: -----------\n%v\n\n", addr, strResp)
}

func getNonce(url string) (*api.NonceResponse, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var retNonce api.NonceResponse
	if err := json.NewDecoder(resp.Body).Decode(&retNonce); err != nil {
		return nil, err
	}

	return &retNonce, nil
}

// Sends jwt to url and returns an api.AttestResponse where api.AttestResponse.OK == true if accepted.
func checkVerify(url string, jwt string) (*api.AttestResponse, error) {
	reader := strings.NewReader(jwt)

	resp, err := http.Post(url, "application/text", reader)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var retResp api.AttestResponse
	if err := json.NewDecoder(resp.Body).Decode(&retResp); err != nil {
		return nil, err
	}

	return &retResp, nil
}
