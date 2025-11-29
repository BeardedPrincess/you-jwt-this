// The holder will operate in two steps:
//  1. Get a nonce value from the verifier server (/nonce)
//  2. Include the nonce as a value in the payload, and submit to the verifier (/verify)
//
//  The server will prevent reuse of the nonce, so a new one must be fetched for each submission

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/beardedprincess/you-jwt-this/internal/api"
	"github.com/beardedprincess/you-jwt-this/internal/crypto"
)

const VERIFY_HOST = "127.0.0.1:8080"

func main() {
	// Generate a keypair used to sign payload
	//. this function doesn't really care how "internal/crypto" handles this, or even what kind of key
	//. is generated/used. This is intentional to create extensibility / improvments later
	pub, priv, err := crypto.GenerateKey()
	_ = priv // TODO: Remove this after testing
	if err != nil {
		log.Fatal(err)
	}

	// TODO:  Figure out how to get the nonce from the serveer
	nonce, err := getNonce(fmt.Sprintf("http://%s/nonce", VERIFY_HOST))
	if err != nil {
		log.Fatal(err)
	}

	// Construct the payload
	var jwt api.Jwt = api.Jwt{
		Header: api.Header{
			Type:      "JWT",
			Algorithm: "EdDSA",
		},
		Payload: api.Payload{
			Nonce:    *nonce,
			Subject:  "Lorem Ipsum",
			Jwk:      crypto.GetJWK(pub),
			Audience: "https://you-jwt-this.beardedprincess.com",
		},
	}

	sig := base64.RawURLEncoding.EncodeToString(crypto.Sign(priv, []byte(jwt.Encode())))

	fmt.Printf("\n---------- BEGIN JWT ---------\n%s.%s\n---------- END JWT ---------\n", string(jwt.Encode()), string(sig))
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
