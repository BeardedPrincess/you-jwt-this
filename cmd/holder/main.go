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
	"strings"

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

	resp, err := checkVerify(fmt.Sprintf("http://%s/verify", VERIFY_HOST), strJwt)
	if err != nil {
		log.Fatal(err)
	}

	// Marshal the response into pretty json for printing purposes
	bResp, err := json.Marshal(resp)
	if err != nil {
		log.Fatal(err)
	}
	strResp := string(bResp)

	fmt.Printf("Response for Verifier: \n%v\n", strResp)
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
