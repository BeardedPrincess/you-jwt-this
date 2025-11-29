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

	"github.com/beardedprincess/you-jwt-this/internal/api"
	"github.com/beardedprincess/you-jwt-this/internal/crypto"
)

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

	// Construct the payload
	var payload api.Payload = api.Payload{
		NonceID:   "Foo",
		Nonce:     "Bar",
		Subject:   "Lorem Ipsum",
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}

	// Convert payload to JSON
	bPayload, err := json.Marshal(payload)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(bPayload))

}
